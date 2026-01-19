# Budget Rate Limit Policy - Implementation Specification

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
├── token-ratelimit/v0.1.0/       # Token-based rate limiting
│   └── ...
│
└── budget-ratelimit/v0.1.0/      # TO BE CREATED
    ├── policy-definition.yaml
    ├── budget_ratelimit.go
    ├── go.mod
    └── go.sum
```

---

## What We're Building

A **budget-ratelimit** policy that limits API usage based on monetary cost calculated from LLM token consumption. Users define pricing per token type (cost per 1M tokens) and set budget limits. The policy computes cost as `tokens × (costPer1MTokens / 1,000,000)` and enforces budget limits.

It follows the **delegation pattern** used by `basic-ratelimit` - exposing a simplified, budget-focused configuration while internally delegating to `advanced-ratelimit`.

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Delegation to advanced-ratelimit | Reuse existing limiter, algorithms, backends |
| Pricing model | Per token type (not model-based) | Model-based requires dynamic multipliers not supported by advanced-ratelimit |
| Budget structure | 3 separate budgets (prompt, completion, total) | Independent budget control per token type |
| Multiple limits per budget | Yes (array of limit/duration pairs) | e.g., $100/hour AND $1000/day |
| Total budget calculation | Computed from prompt + completion pricing | Sum of (promptTokens × promptPrice) + (completionTokens × completionPrice) |
| Currency units | Implicit (numbers only) | Keep it simple, documentation specifies units |
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
    pricing:
      type: object
      description: Token pricing configuration
      required: ["promptTokens", "completionTokens"]
      properties:
        promptTokens:
          type: object
          description: Pricing for prompt/input tokens
          required: ["costPer1MTokens", "jsonPath"]
          properties:
            costPer1MTokens:
              type: number
              minimum: 0
              description: Cost per 1 million prompt tokens (e.g., 10.00 for $10/1M tokens)
              example: 10.00
            jsonPath:
              type: string
              description: JSON path to extract prompt token count from response body
              example: "$.usage.prompt_tokens"
        completionTokens:
          type: object
          description: Pricing for completion/output tokens
          required: ["costPer1MTokens", "jsonPath"]
          properties:
            costPer1MTokens:
              type: number
              minimum: 0
              description: Cost per 1 million completion tokens (e.g., 30.00 for $30/1M tokens)
              example: 30.00
            jsonPath:
              type: string
              description: JSON path to extract completion token count from response body
              example: "$.usage.completion_tokens"

    promptBudget:
      type: object
      description: Budget limit for prompt token costs only
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: number
                minimum: 0
                description: Maximum budget (cost units) allowed in the duration
              duration:
                type: string
                pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"
                description: Time window for the budget limit

    completionBudget:
      type: object
      description: Budget limit for completion token costs only
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: number
                minimum: 0
              duration:
                type: string

    totalBudget:
      type: object
      description: Budget limit for combined prompt + completion costs
      properties:
        limits:
          type: array
          minItems: 1
          items:
            type: object
            required: ["limit", "duration"]
            properties:
              limit:
                type: number
                minimum: 0
              duration:
                type: string

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

### 1. Cost Calculation

The cost is calculated using the multiplier feature in advanced-ratelimit:

```
multiplier = costPer1MTokens / 1,000,000

Example:
- promptTokens.costPer1MTokens = 10.00
- multiplier = 10.00 / 1,000,000 = 0.00001
- If response has 5000 prompt tokens: cost = 5000 × 0.00001 = 0.05
```

### 2. Transform Configuration

`budget_ratelimit.go` transforms user config to advanced-ratelimit quotas:

```go
func transformToRatelimitParams(params map[string]interface{}, metadata policy.PolicyMetadata) map[string]interface{} {
    quotas := []interface{}{}
    
    // Determine key extraction based on attachment level
    keyExtractorType := "routename"
    if metadata.AttachedTo == policy.LevelAPI {
        keyExtractorType = "apiname"
    }
    
    // Extract pricing configuration
    pricing := params["pricing"].(map[string]interface{})
    promptPricing := pricing["promptTokens"].(map[string]interface{})
    completionPricing := pricing["completionTokens"].(map[string]interface{})
    
    // Calculate multipliers (cost per token)
    promptMultiplier := promptPricing["costPer1MTokens"].(float64) / 1_000_000
    completionMultiplier := completionPricing["costPer1MTokens"].(float64) / 1_000_000
    
    // Build quota for promptBudget if configured
    if promptBudget, ok := params["promptBudget"].(map[string]interface{}); ok {
        quotas = append(quotas, map[string]interface{}{
            "name":   "prompt-budget",
            "limits": promptBudget["limits"],
            "keyExtraction": []interface{}{
                map[string]interface{}{"type": keyExtractorType},
            },
            "costExtraction": map[string]interface{}{
                "enabled": true,
                "sources": []interface{}{
                    map[string]interface{}{
                        "type":       "response_body",
                        "jsonPath":   promptPricing["jsonPath"],
                        "multiplier": promptMultiplier,
                    },
                },
                "default": getDefaultCost(params, promptMultiplier),
            },
        })
    }
    
    // Build quota for completionBudget if configured
    if completionBudget, ok := params["completionBudget"].(map[string]interface{}); ok {
        quotas = append(quotas, map[string]interface{}{
            "name":   "completion-budget",
            "limits": completionBudget["limits"],
            "keyExtraction": []interface{}{
                map[string]interface{}{"type": keyExtractorType},
            },
            "costExtraction": map[string]interface{}{
                "enabled": true,
                "sources": []interface{}{
                    map[string]interface{}{
                        "type":       "response_body",
                        "jsonPath":   completionPricing["jsonPath"],
                        "multiplier": completionMultiplier,
                    },
                },
                "default": getDefaultCost(params, completionMultiplier),
            },
        })
    }
    
    // Build quota for totalBudget if configured
    // Uses both sources with their respective multipliers - advanced-ratelimit sums them
    if totalBudget, ok := params["totalBudget"].(map[string]interface{}); ok {
        quotas = append(quotas, map[string]interface{}{
            "name":   "total-budget",
            "limits": totalBudget["limits"],
            "keyExtraction": []interface{}{
                map[string]interface{}{"type": keyExtractorType},
            },
            "costExtraction": map[string]interface{}{
                "enabled": true,
                "sources": []interface{}{
                    map[string]interface{}{
                        "type":       "response_body",
                        "jsonPath":   promptPricing["jsonPath"],
                        "multiplier": promptMultiplier,
                    },
                    map[string]interface{}{
                        "type":       "response_body",
                        "jsonPath":   completionPricing["jsonPath"],
                        "multiplier": completionMultiplier,
                    },
                },
                "default": getDefaultCost(params, promptMultiplier + completionMultiplier),
            },
        })
    }
    
    // Build final params with quotas and pass-through system params
    rlParams := map[string]interface{}{
        "quotas": quotas,
    }
    
    // Pass through system parameters
    if algorithm, ok := params["algorithm"]; ok {
        rlParams["algorithm"] = algorithm
    }
    if backend, ok := params["backend"]; ok {
        rlParams["backend"] = backend
    }
    if redis, ok := params["redis"]; ok {
        rlParams["redis"] = redis
    }
    if memory, ok := params["memory"]; ok {
        rlParams["memory"] = memory
    }
    
    return rlParams
}

// getDefaultCost calculates default cost based on onExtractionFailure settings
func getDefaultCost(params map[string]interface{}, multiplier float64) float64 {
    if onFailure, ok := params["onExtractionFailure"].(map[string]interface{}); ok {
        if action, ok := onFailure["action"].(string); ok && action == "default" {
            if defaultValue, ok := onFailure["defaultValue"].(float64); ok {
                return defaultValue * multiplier
            }
        }
    }
    return 0 // skip action = 0 cost
}
```

### 3. Handle onExtractionFailure

| Action | Implementation |
|--------|----------------|
| `skip` | Set `costExtraction.default: 0` |
| `default` | Set `costExtraction.default: defaultValue × multiplier` |
| `reject` | Requires enhancement to advanced-ratelimit OR handle in OnResponse |

### 4. Processing Mode

Since we extract from **response body**, the policy must buffer responses:

```go
func (p *BudgetRateLimitPolicy) Mode() policy.ProcessingMode {
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

### Simple: Total budget only
```yaml
pricing:
  promptTokens:
    costPer1MTokens: 10.00
    jsonPath: "$.usage.prompt_tokens"
  completionTokens:
    costPer1MTokens: 30.00
    jsonPath: "$.usage.completion_tokens"

totalBudget:
  limits:
    - limit: 100.00    # $100/hour
      duration: "1h"
```

### Granular: Separate budgets
```yaml
pricing:
  promptTokens:
    costPer1MTokens: 10.00
    jsonPath: "$.usage.prompt_tokens"
  completionTokens:
    costPer1MTokens: 30.00
    jsonPath: "$.usage.completion_tokens"

promptBudget:
  limits:
    - limit: 50.00
      duration: "1h"

completionBudget:
  limits:
    - limit: 80.00
      duration: "1h"

totalBudget:
  limits:
    - limit: 100.00
      duration: "1h"
```

### Multi-window budget limits
```yaml
pricing:
  promptTokens:
    costPer1MTokens: 2.50      # GPT-4 Turbo input pricing
    jsonPath: "$.usage.prompt_tokens"
  completionTokens:
    costPer1MTokens: 10.00     # GPT-4 Turbo output pricing
    jsonPath: "$.usage.completion_tokens"

totalBudget:
  limits:
    - limit: 10.00       # $10/minute burst limit
      duration: "1m"
    - limit: 100.00      # $100/hour
      duration: "1h"
    - limit: 1000.00     # $1000/day
      duration: "24h"

onExtractionFailure:
  action: "default"
  defaultValue: 100      # Assume 100 tokens if extraction fails
```

### OpenAI-style pricing
```yaml
pricing:
  promptTokens:
    costPer1MTokens: 0.50      # GPT-3.5 Turbo input
    jsonPath: "$.usage.prompt_tokens"
  completionTokens:
    costPer1MTokens: 1.50      # GPT-3.5 Turbo output
    jsonPath: "$.usage.completion_tokens"

totalBudget:
  limits:
    - limit: 50.00
      duration: "1h"
```

---

## Validation Rules

1. `pricing` is required with both `promptTokens` and `completionTokens`
2. Each pricing config must have `costPer1MTokens` and `jsonPath`
3. At least one of `promptBudget`, `completionBudget`, or `totalBudget` must be configured
4. Each configured budget must have at least one limit
5. `costPer1MTokens` must be >= 0
6. `onExtractionFailure.defaultValue` only used when `action: "default"`

---

## Files to Create

```
gateway/policies/budget-ratelimit/v0.1.0/
├── policy-definition.yaml   # Schema above
├── budget_ratelimit.go      # Transform + delegate pattern
├── go.mod                   # Dependencies on advanced-ratelimit, policy SDK
└── go.sum
```
