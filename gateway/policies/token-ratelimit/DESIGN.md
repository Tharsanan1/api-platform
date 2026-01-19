# Token Rate Limit Policy - Implementation Specification

## Context & Location

**Policies Directory Structure:**
```
gateway/policies/
├── advanced-ratelimit/v0.1.0/    # Core rate limiting engine
│   ├── policy-definition.yaml    # Full schema with quotas, costExtraction
│   ├── ratelimit.go              # Main policy implementation
│   ├── cost_extractor.go         # JSON path extraction logic
│   ├── algorithms/               # GCRA, Fixed-Window implementations
│   └── limiter/                  # Backend abstraction (memory/redis)
│
├── basic-ratelimit/v0.1.0/       # Simple wrapper (delegation pattern)
│   ├── policy-definition.yaml    # Simplified schema (just limits array)
│   └── basic_ratelimit.go        # Transforms config & delegates to advanced-ratelimit
│
└── token-ratelimit/v0.1.0/       # TO BE CREATED
    ├── policy-definition.yaml
    ├── token_ratelimit.go
    ├── go.mod
    └── go.sum
```

---

## What We're Building

A **token-ratelimit** policy that limits API usage based on LLM token consumption (prompt tokens, completion tokens, total tokens). It follows the **delegation pattern** used by `basic-ratelimit` - exposing a simplified, token-focused configuration while internally delegating to `advanced-ratelimit`.

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Delegation to advanced-ratelimit | Reuse existing limiter, algorithms, backends |
| Quota structure | 3 separate quotas (prompt, completion, total) | Independent limits per token type |
| Multiple limits per type | Yes (array of limit/duration pairs) | e.g., 1000/min AND 50000/hour |
| Total tokens extraction | Extract if jsonPath provided, else compute from prompt+completion | Flexibility |
| Multipliers/weights | Not supported | Keep it simple |
| Key extraction | Auto-determined by attachment level | `apiname` for API-level, `routename` for route-level |
| Extraction failure | Configurable via `onExtractionFailure` | User controls behavior |

---

## Configuration Schema

### Parameters (User-Facing)

```yaml
parameters:
  type: object
  additionalProperties: false
  properties:
    promptTokens:
      type: object
      description: Rate limit based on prompt/input tokens
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: integer
                minimum: 1
              duration:
                type: string
                pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"
        jsonPath:
          type: string
          description: JSON path to extract prompt token count from response body
          example: "$.usage.prompt_tokens"

    completionTokens:
      type: object
      description: Rate limit based on completion/output tokens
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: integer
                minimum: 1
              duration:
                type: string
        jsonPath:
          type: string
          description: JSON path to extract completion token count from response body
          example: "$.usage.completion_tokens"

    totalTokens:
      type: object
      description: Rate limit based on total tokens (extracted or computed)
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: integer
                minimum: 1
              duration:
                type: string
        jsonPath:
          type: string
          description: |
            JSON path to extract total token count. If omitted and both
            promptTokens and completionTokens are configured, total is
            computed as prompt + completion.
          example: "$.usage.total_tokens"

    onExtractionFailure:
      type: object
      description: Behavior when token count cannot be extracted from response
      properties:
        action:
          type: string
          enum: ["skip", "default", "reject"]
          default: "skip"
          description: |
            - skip: Don't count this request (fail-open)
            - default: Use defaultValue as the token count
            - reject: Return error response
        defaultValue:
          type: integer
          minimum: 0
          default: 0
          description: Token count to use when action=default
```

### System Parameters (Pass-through to advanced-ratelimit)

```yaml
systemParameters:
  type: object
  properties:
    algorithm:
      type: string
      enum: ["gcra", "fixed-window"]
      default: "gcra"
    backend:
      type: string
      enum: ["memory", "redis"]
      default: "memory"
    redis:
      type: object
      properties:
        host: { type: string, default: "localhost" }
        port: { type: integer, default: 6379 }
        password: { type: string }
        username: { type: string }
        db: { type: integer, default: 0 }
        keyPrefix: { type: string, default: "ratelimit:v1:" }
        failureMode: { type: string, enum: ["open", "closed"], default: "open" }
        connectionTimeout: { type: string, default: "5s" }
        readTimeout: { type: string, default: "3s" }
        writeTimeout: { type: string, default: "3s" }
    memory:
      type: object
      properties:
        maxEntries: { type: integer, default: 10000 }
        cleanupInterval: { type: string, default: "5m" }
    headers:
      type: object
      properties:
        includeXRateLimit: { type: boolean, default: true }
        includeIETF: { type: boolean, default: true }
        includeRetryAfter: { type: boolean, default: true }
```

---

## Implementation Approach

### 1. Transform Configuration

`token_ratelimit.go` transforms user config to advanced-ratelimit quotas:

```go
func transformToRatelimitParams(params map[string]interface{}, metadata policy.PolicyMetadata) map[string]interface{} {
    quotas := []interface{}{}
    
    // Determine key extraction based on attachment level
    keyExtractorType := "routename"
    if metadata.AttachedTo == policy.LevelAPI {
        keyExtractorType = "apiname"
    }
    
    // Build quota for promptTokens if configured
    if promptTokens, ok := params["promptTokens"].(map[string]interface{}); ok {
        quotas = append(quotas, map[string]interface{}{
            "name":   "prompt-tokens",
            "limits": promptTokens["limits"],
            "keyExtraction": []interface{}{
                map[string]interface{}{"type": keyExtractorType},
            },
            "costExtraction": map[string]interface{}{
                "enabled": true,
                "sources": []interface{}{
                    map[string]interface{}{
                        "type":     "response_body",
                        "jsonPath": promptTokens["jsonPath"],
                    },
                },
                "default": getDefaultValue(params), // from onExtractionFailure
            },
        })
    }
    
    // Similar for completionTokens...
    // Similar for totalTokens (with computed logic if no jsonPath)...
    
    return rlParams
}
```

### 2. Handle Computed Total Tokens

If `totalTokens` is configured without `jsonPath`, and both `promptTokens` and `completionTokens` have `jsonPath`:
- Create a quota that sums both sources (using advanced-ratelimit's multi-source summing)

```go
// totalTokens computed from prompt + completion
"costExtraction": map[string]interface{}{
    "enabled": true,
    "sources": []interface{}{
        map[string]interface{}{
            "type":       "response_body",
            "jsonPath":   promptTokens["jsonPath"],
            "multiplier": 1.0,
        },
        map[string]interface{}{
            "type":       "response_body",
            "jsonPath":   completionTokens["jsonPath"],
            "multiplier": 1.0,
        },
    },
},
```

### 3. Handle onExtractionFailure

| Action | Implementation |
|--------|----------------|
| `skip` | Set `costExtraction.default: 0` |
| `default` | Set `costExtraction.default: <defaultValue>` |
| `reject` | Requires enhancement to advanced-ratelimit OR handle in OnResponse |

### 4. Processing Mode

Since we extract from **response body**, the policy must buffer responses:

```go
func (p *TokenRateLimitPolicy) Mode() policy.ProcessingMode {
    return policy.ProcessingMode{
        RequestHeaderMode:  policy.HeaderModeProcess,
        RequestBodyMode:    policy.BodyModeSkip,
        ResponseHeaderMode: policy.HeaderModeProcess,
        ResponseBodyMode:   policy.BodyModeBuffer, // Required for extraction
    }
}
```

---

## Example Configurations

### Simple: Total tokens only
```yaml
totalTokens:
  limits:
    - limit: 100000
      duration: "1h"
  jsonPath: "$.usage.total_tokens"
```

### Granular: Separate limits
```yaml
promptTokens:
  limits:
    - limit: 50000
      duration: "1h"
  jsonPath: "$.usage.prompt_tokens"
completionTokens:
  limits:
    - limit: 30000
      duration: "1h"
  jsonPath: "$.usage.completion_tokens"
```

### Multi-window limits
```yaml
totalTokens:
  limits:
    - limit: 10000
      duration: "1m"
    - limit: 500000
      duration: "1h"
    - limit: 5000000
      duration: "24h"
  jsonPath: "$.usage.total_tokens"
onExtractionFailure:
  action: "default"
  defaultValue: 100
```

---

## Validation Rules

1. At least one of `promptTokens`, `completionTokens`, or `totalTokens` must be configured
2. Each configured token type must have at least one limit
3. If `totalTokens` has no `jsonPath`, both `promptTokens.jsonPath` AND `completionTokens.jsonPath` must be provided (for computation)
4. `onExtractionFailure.defaultValue` only used when `action: "default"`

---

## Files to Create

```
gateway/policies/token-ratelimit/v0.1.0/
├── policy-definition.yaml   # Schema above
├── token_ratelimit.go       # Transform + delegate pattern
├── go.mod                   # Dependencies on advanced-ratelimit, policy SDK
└── go.sum
```
