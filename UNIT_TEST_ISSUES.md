# Unit Test Issues for Gateway Policies

This document contains comprehensive GitHub issue templates for creating unit tests for 22 gateway policies in `gateway/policies/` that currently lack test coverage.

## Summary

- **Total policies:** 25
- **Policies with tests:** 3 (jwt-auth, mcp-auth, advanced-ratelimit/algorithms)
- **Policies needing tests:** 22

## Reference Test Examples

Before creating tests for your assigned policy, please review these existing test files:
- `gateway/policies/jwt-auth/v0.1.0/jwtauth_test.go` - Comprehensive authentication policy tests with mocking, test helpers, and edge case coverage
- `gateway/policies/mcp-auth/v0.1.0/mcp-auth_test.go` - MCP authentication policy tests demonstrating delegation patterns

These examples demonstrate:
- How to create mock request/response contexts
- How to test policy configuration parsing
- How to validate policy actions (ImmediateResponse, UpstreamRequestModifications, etc.)
- How to test error handling and edge cases
- How to organize test helper functions

## How to Run Tests

After implementing your unit tests, run the following commands before submitting your PR:

```bash
# Navigate to your policy directory
cd gateway/policies/<policy-name>/v0.1.0

# Run tests with verbose output
go test -v ./...

# Run tests with coverage report
go test -v -cover ./...

# Generate detailed coverage HTML report (recommended)
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Target:** Aim for **>80% code coverage** for all new tests.

---

## General Testing Guidelines

For ALL policies, your tests should include:

1. **Test Policy Initialization**
   - Test `GetPolicy()` with valid parameters
   - Test `GetPolicy()` with invalid/missing parameters
   - Verify policy returns expected error messages

2. **Test Processing Mode**
   - Verify `Mode()` returns correct header/body processing modes

3. **Test Core Functionality**
   - Test successful execution with valid inputs
   - Test with various parameter combinations
   - Test with edge cases (empty values, nulls, boundaries)

4. **Test Error Handling**
   - Test with missing required parameters
   - Test with invalid data formats
   - Test with boundary violations

5. **Test Metadata Handling**
   - Verify correct metadata is set in context
   - Test metadata propagation between request/response

6. **Test Action Types**
   - Verify correct action type is returned (ImmediateResponse vs UpstreamRequestModifications/UpstreamResponseModifications)
   - Verify action contains expected data

---

## Issues to Create

Each section below represents a separate GitHub issue. Copy the entire issue template and create a new GitHub issue.


---

## Issue 1: Add unit tests for api-key-auth policy

**Title:** Add unit tests for api-key-auth policy

**Labels:** `testing`, `enhancement`, `policy`, `security`, `authentication`

**Description:**

### Policy Location
`gateway/policies/api-key-auth/v0.1.0/`

### Test File to Create
`gateway/policies/api-key-auth/v0.1.0/apikey_test.go`

### Overview
The api-key-auth policy implements API Key Authentication by extracting API keys from headers or query parameters, optionally stripping prefixes, and validating them against an external API key store.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` returns non-nil policy
- ✅ Test `Mode()` returns correct processing mode (HeaderModeProcess for request, BodyModeSkip)

#### 2. Successful Authentication Tests
- ✅ Test API key authentication via header (e.g., `X-API-Key`)
- ✅ Test API key authentication via query parameter
- ✅ Test with value prefix (e.g., `ApiKey <key>`) - verify prefix is stripped
- ✅ Test without value prefix - verify key is used as-is
- ✅ Verify `auth.success=true` and `auth.method="api-key"` metadata is set
- ✅ Verify `UpstreamRequestModifications` action is returned

#### 3. Authentication Failure Tests
- ✅ Test missing API key (no header, no query param)
- ✅ Test invalid API key location (not "header" or "query")
- ✅ Test API key that becomes empty after prefix removal
- ✅ Test missing required configuration parameters (`key`, `in`)
- ✅ Test missing API metadata (APIId, APIName, APIVersion, OperationPath, Method)
- ✅ Verify `auth.success=false` metadata is set on failures
- ✅ Verify `ImmediateResponse` with status 401 is returned
- ✅ Verify error response format (JSON)

#### 4. Edge Cases
- ✅ Test case-insensitive header matching
- ✅ Test query parameter URL decoding
- ✅ Test query parameter with special characters
- ✅ Test empty string API key
- ✅ Test whitespace-only API key

#### 5. Integration with API Key Store
- ✅ Mock `policy.GetAPIkeyStoreInstance()` for validation
- ✅ Test validation success scenario
- ✅ Test validation failure scenario
- ✅ Test validation error handling

### Implementation Guidelines

1. Create helper functions:
   ```go
   func createMockRequestContext(headers map[string][]string, path string) *policy.RequestContext
   func createMockAPIKeyStore() // Mock the API key store
   ```

2. Test structure example:
   ```go
   func TestAPIKeyAuthPolicy_HeaderAuth_Success(t *testing.T) {
       // Setup: Create context with API key in header
       // Execute: Call OnRequest
       // Verify: Check metadata, action type, headers
   }
   ```

3. Mock external dependencies:
   - Mock `policy.GetAPIkeyStoreInstance()` to return test validation results
   - Set API metadata in RequestContext (APIId, APIName, APIVersion, OperationPath, Method)

4. Test both JSON and plain text error formats

### Before Submitting PR

Run these commands and ensure all tests pass:

```bash
cd gateway/policies/api-key-auth/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] Test code follows patterns from jwt-auth and mcp-auth examples
- [ ] Helper functions are well-documented
- [ ] Edge cases are thoroughly tested

---

## Issue 2: Add unit tests for basic-auth policy

**Title:** Add unit tests for basic-auth policy

**Labels:** `testing`, `enhancement`, `policy`, `security`, `authentication`

**Description:**

### Policy Location
`gateway/policies/basic-auth/v0.1.0/`

### Test File to Create
`gateway/policies/basic-auth/v0.1.0/basicauth_test.go`

### Overview
The basic-auth policy implements HTTP Basic Authentication by extracting and validating Base64-encoded credentials from the Authorization header against configured username/password.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` returns non-nil policy
- ✅ Test `Mode()` returns correct processing mode

#### 2. Successful Authentication Tests
- ✅ Test valid Basic auth credentials
- ✅ Test with default realm ("Restricted")
- ✅ Test with custom realm parameter
- ✅ Verify `auth.success=true`, `auth.username` and `auth.method="basic"` metadata is set
- ✅ Verify `UpstreamRequestModifications` action is returned

#### 3. Authentication Failure Tests
- ✅ Test missing Authorization header
- ✅ Test wrong authentication scheme (e.g., "Bearer" instead of "Basic")
- ✅ Test invalid Base64 encoding
- ✅ Test malformed credentials (missing colon separator)
- ✅ Test wrong username
- ✅ Test wrong password
- ✅ Test correct username but wrong password
- ✅ Verify `auth.success=false` metadata is set on failures
- ✅ Verify `ImmediateResponse` with status 401 and WWW-Authenticate header

#### 4. Allow Unauthenticated Mode Tests
- ✅ Test with `allowUnauthenticated=true` - request should proceed even without credentials
- ✅ Test with `allowUnauthenticated=true` and invalid credentials - request should still proceed
- ✅ Verify metadata indicates failed auth but request continues

#### 5. Edge Cases
- ✅ Test empty username
- ✅ Test empty password
- ✅ Test credentials with special characters
- ✅ Test credentials with Unicode characters
- ✅ Test credentials with colons in password (e.g., "user:pass:word")
- ✅ Test Base64 with padding characters
- ✅ Test Base64 without padding
- ✅ Test credentials with whitespace

#### 6. Response Headers
- ✅ Verify WWW-Authenticate header format: `Basic realm="<realm>"`
- ✅ Verify Content-Type header: `application/json`

### Implementation Guidelines

1. Create helper functions:
   ```go
   func createBasicAuthHeader(username, password string) string
   func createMockRequestContext(headers map[string][]string) *policy.RequestContext
   ```

2. Use Go's standard encoding/base64 package to create test credentials

3. Test structure example:
   ```go
   func TestBasicAuthPolicy_ValidCredentials(t *testing.T) {
       params := map[string]interface{}{
           "username": "testuser",
           "password": "testpass",
       }
       authHeader := createBasicAuthHeader("testuser", "testpass")
       ctx := createMockRequestContext(map[string][]string{
           "authorization": {authHeader},
       })
       // Test execution and validation
   }
   ```

### Before Submitting PR

```bash
cd gateway/policies/basic-auth/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] Both success and failure paths are tested
- [ ] allowUnauthenticated behavior is thoroughly tested
- [ ] WWW-Authenticate header is validated in failure cases

---

## Issue 3: Add unit tests for cors policy

**Title:** Add unit tests for cors policy

**Labels:** `testing`, `enhancement`, `policy`, `security`

**Description:**

### Policy Location
`gateway/policies/cors/v0.1.0/`

### Test File to Create
`gateway/policies/cors/v0.1.0/cors_test.go`

### Overview
The cors policy implements Cross-Origin Resource Sharing (CORS) by handling preflight OPTIONS requests and adding appropriate CORS headers to both preflight and actual responses.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` with valid default parameters
- ✅ Test `GetPolicy()` with wildcard origin (`*`)
- ✅ Test `GetPolicy()` with specific origins
- ✅ Test `GetPolicy()` with regex pattern origins
- ✅ Test `GetPolicy()` with invalid regex patterns (should return error)
- ✅ Test `GetPolicy()` with `allowCredentials=true` and wildcard origin (should return error)
- ✅ Test `GetPolicy()` with `allowCredentials=true` and wildcard headers (should return error)
- ✅ Test `GetPolicy()` with `allowCredentials=true` and wildcard methods (should return error)
- ✅ Test `GetPolicy()` with `allowCredentials=true` and wildcard exposed headers (should return error)
- ✅ Test `Mode()` returns correct processing mode (HeaderModeProcess for both request and response)

#### 2. Preflight Request Tests (OPTIONS)
- ✅ Test successful preflight with wildcard origin
- ✅ Test successful preflight with matching specific origin
- ✅ Test successful preflight with matching regex origin
- ✅ Test preflight with non-matching origin (should fail CORS validation)
- ✅ Test preflight with disallowed method (should fail CORS validation)
- ✅ Test preflight with disallowed headers (should fail CORS validation)
- ✅ Test preflight with wildcard headers and Access-Control-Request-Headers
- ✅ Test preflight with specific allowed headers
- ✅ Test preflight returns 204 status code
- ✅ Test preflight with `forwardPreflight=true` on CORS failure
- ✅ Test preflight with `forwardPreflight=false` on CORS failure (default)
- ✅ Verify Access-Control-Max-Age header when maxAge is configured
- ✅ Verify Access-Control-Allow-Credentials header when allowCredentials is true

#### 3. Non-Preflight Request Tests (GET, POST, etc.)
- ✅ Test non-preflight with wildcard origin
- ✅ Test non-preflight with matching specific origin
- ✅ Test non-preflight with matching regex origin
- ✅ Test non-preflight with non-matching origin (no CORS headers added)
- ✅ Test non-preflight with missing Origin header
- ✅ Verify CORS headers are stored in metadata for response phase
- ✅ Verify Vary: Origin header for non-wildcard origins

#### 4. Response Phase Tests
- ✅ Test `OnResponse()` adds CORS headers from metadata
- ✅ Test `OnResponse()` when no CORS headers in metadata
- ✅ Test Access-Control-Expose-Headers is included when configured
- ✅ Test Access-Control-Allow-Credentials in response

#### 5. Edge Cases
- ✅ Test with empty allowedOrigins array
- ✅ Test with multiple origins in allowedOrigins
- ✅ Test with case-sensitive origin matching
- ✅ Test comma-separated Access-Control-Request-Headers
- ✅ Test headers with whitespace
- ✅ Test wildcard (*) with multiple allowedOrigins (wildcard should take precedence)

#### 6. Configuration Combinations
- ✅ Test with all default parameters
- ✅ Test with custom allowedMethods
- ✅ Test with custom allowedHeaders
- ✅ Test with custom exposedHeaders
- ✅ Test with maxAge set to 0, negative, and positive values
- ✅ Test allowCredentials true and false

### Implementation Guidelines

1. Create helper functions:
   ```go
   func createPreflightRequest(origin, method string, headers []string) *policy.RequestContext
   func createNonPreflightRequest(origin, method string) *policy.RequestContext
   func createMockResponseContext(reqMetadata map[string]interface{}) *policy.ResponseContext
   ```

2. Test structure example:
   ```go
   func TestCorsPolicy_Preflight_WildcardOrigin(t *testing.T) {
       params := map[string]interface{}{
           "allowedOrigins": []interface{}{"*"},
           "allowedMethods": []interface{}{"GET", "POST"},
       }
       p, err := GetPolicy(policy.PolicyMetadata{}, params)
       ctx := createPreflightRequest("https://example.com", "POST", []string{"Content-Type"})
       action := p.OnRequest(ctx, params)
       // Validate ImmediateResponse with 204 status and CORS headers
   }
   ```

3. Validate header values precisely:
   - Access-Control-Allow-Origin
   - Access-Control-Allow-Methods
   - Access-Control-Allow-Headers
   - Access-Control-Max-Age
   - Access-Control-Allow-Credentials
   - Access-Control-Expose-Headers
   - Vary

### Before Submitting PR

```bash
cd gateway/policies/cors/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] Both preflight and non-preflight scenarios are tested
- [ ] Policy initialization validation is thoroughly tested
- [ ] Response phase CORS header injection is tested
- [ ] Edge cases with allowCredentials are covered

---

## Issue 4: Add unit tests for modify-headers policy

**Title:** Add unit tests for modify-headers policy

**Labels:** `testing`, `enhancement`, `policy`

**Description:**

### Policy Location
`gateway/policies/modify-headers/v0.1.0/`

### Test File to Create
`gateway/policies/modify-headers/v0.1.0/modifyheaders_test.go`

### Overview
The modify-headers policy implements header manipulation for both request and response phases, supporting SET, APPEND, and DELETE operations.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` returns non-nil policy
- ✅ Test `Mode()` returns correct processing mode (HeaderModeProcess for both request and response)

#### 2. Request Header Modification Tests
- ✅ Test SET action - sets header value
- ✅ Test APPEND action - appends to existing header
- ✅ Test DELETE action - removes header
- ✅ Test multiple SET operations
- ✅ Test multiple APPEND operations
- ✅ Test multiple DELETE operations
- ✅ Test mixed actions (SET, APPEND, DELETE) in single policy
- ✅ Test with no requestHeaders configuration (pass-through)
- ✅ Verify `UpstreamRequestModifications` with correct SetHeaders, AppendHeaders, RemoveHeaders maps

#### 3. Response Header Modification Tests
- ✅ Test SET action on response headers
- ✅ Test APPEND action on response headers
- ✅ Test DELETE action on response headers
- ✅ Test multiple modifications
- ✅ Test with no responseHeaders configuration (pass-through)
- ✅ Verify `UpstreamResponseModifications` with correct header maps

#### 4. Configuration Validation Tests
- ✅ Test with empty requestHeaders array
- ✅ Test with empty responseHeaders array
- ✅ Test with invalid action type (not SET/APPEND/DELETE)
- ✅ Test with missing 'name' field
- ✅ Test with missing 'value' field for SET action
- ✅ Test with missing 'value' field for APPEND action
- ✅ Test DELETE action without 'value' field (should be valid)

#### 5. Edge Cases
- ✅ Test header names are normalized to lowercase
- ✅ Test action names are case-insensitive (set, SET, Set)
- ✅ Test empty string header value
- ✅ Test header value with special characters
- ✅ Test header value with Unicode
- ✅ Test setting standard HTTP headers (Content-Type, Authorization, etc.)
- ✅ Test deleting non-existent headers

#### 6. Both Request and Response Phases
- ✅ Test policy with both requestHeaders and responseHeaders configured
- ✅ Test policy with only requestHeaders configured
- ✅ Test policy with only responseHeaders configured
- ✅ Test policy with neither configured (should pass through)

### Implementation Guidelines

1. Create helper functions:
   ```go
   func createHeaderModification(action, name, value string) map[string]interface{}
   func createMockRequestContext() *policy.RequestContext
   func createMockResponseContext() *policy.ResponseContext
   ```

2. Test structure example:
   ```go
   func TestModifyHeadersPolicy_Request_SetAction(t *testing.T) {
       params := map[string]interface{}{
           "requestHeaders": []interface{}{
               map[string]interface{}{
                   "action": "SET",
                   "name":   "X-Custom-Header",
                   "value":  "test-value",
               },
           },
       }
       p, _ := GetPolicy(policy.PolicyMetadata{}, params)
       ctx := createMockRequestContext()
       action := p.OnRequest(ctx, params)
       
       modifications := action.(policy.UpstreamRequestModifications)
       if modifications.SetHeaders["x-custom-header"] != "test-value" {
           t.Errorf("Expected header to be set")
       }
   }
   ```

3. Test all three action types (SET, APPEND, DELETE) independently and in combination

4. Verify header name normalization (should be lowercase)

### Before Submitting PR

```bash
cd gateway/policies/modify-headers/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] All three actions (SET, APPEND, DELETE) are thoroughly tested
- [ ] Both request and response phases are tested
- [ ] Configuration validation is tested
- [ ] Edge cases with header names and values are covered

---

## Issue 5: Add unit tests for respond policy

**Title:** Add unit tests for respond policy

**Labels:** `testing`, `enhancement`, `policy`

**Description:**

### Policy Location
`gateway/policies/respond/v0.1.0/`

### Test File to Create
`gateway/policies/respond/v0.1.0/respond_test.go`

### Overview
The respond policy immediately returns a configured response to the client, terminating request processing without forwarding to upstream.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` returns non-nil policy
- ✅ Test `Mode()` returns correct processing mode (HeaderModeProcess for request, skip for response)

#### 2. Basic Response Tests
- ✅ Test immediate response with default statusCode (200)
- ✅ Test immediate response with custom statusCode (201, 400, 404, 500, etc.)
- ✅ Test immediate response with string body
- ✅ Test immediate response with empty body
- ✅ Test immediate response with nil body
- ✅ Verify `ImmediateResponse` action is returned

#### 3. Response Headers Tests
- ✅ Test response with no headers
- ✅ Test response with single header
- ✅ Test response with multiple headers
- ✅ Test response with Content-Type header
- ✅ Test response with custom headers
- ✅ Verify headers array format in params

#### 4. Status Code Tests
- ✅ Test with statusCode as integer (int)
- ✅ Test with statusCode as float64 (JSON number parsing)
- ✅ Test common status codes: 200, 201, 204, 400, 401, 403, 404, 500, 503
- ✅ Test edge case status codes: 100, 599

#### 5. Body Format Tests
- ✅ Test body as string
- ✅ Test body as []byte
- ✅ Test body with JSON content
- ✅ Test body with plain text
- ✅ Test body with HTML content
- ✅ Test body with special characters
- ✅ Test body with Unicode

#### 6. Edge Cases
- ✅ Test with missing statusCode (should default to 200)
- ✅ Test with missing body (should be nil)
- ✅ Test with missing headers (should be empty map)
- ✅ Test with invalid statusCode type
- ✅ Test with invalid body type
- ✅ Test with invalid headers format

#### 7. OnResponse Tests
- ✅ Test `OnResponse()` returns nil (not used by this policy)

### Implementation Guidelines

1. Create helper function:
   ```go
   func createMockRequestContext() *policy.RequestContext
   ```

2. Test structure example:
   ```go
   func TestRespondPolicy_CustomStatusAndBody(t *testing.T) {
       params := map[string]interface{}{
           "statusCode": 404,
           "body":       "Not Found",
           "headers": []interface{}{
               map[string]interface{}{
                   "name":  "Content-Type",
                   "value": "text/plain",
               },
           },
       }
       
       p, _ := GetPolicy(policy.PolicyMetadata{}, params)
       ctx := createMockRequestContext()
       action := p.OnRequest(ctx, params)
       
       response := action.(policy.ImmediateResponse)
       if response.StatusCode != 404 {
           t.Errorf("Expected status 404, got %d", response.StatusCode)
       }
       if string(response.Body) != "Not Found" {
           t.Errorf("Unexpected body")
       }
   }
   ```

3. Test various status codes and body formats

4. Validate headers are correctly formatted in ImmediateResponse

### Before Submitting PR

```bash
cd gateway/policies/respond/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] Various status codes are tested
- [ ] Different body formats are tested
- [ ] Headers configuration is tested
- [ ] OnResponse behavior is verified

---

## Issue 6: Add unit tests for basic-ratelimit policy

**Title:** Add unit tests for basic-ratelimit policy

**Labels:** `testing`, `enhancement`, `policy`, `ratelimit`

**Description:**

### Policy Location
`gateway/policies/basic-ratelimit/v0.1.0/`

### Test File to Create
`gateway/policies/basic-ratelimit/v0.1.0/basic_ratelimit_test.go`

### Overview
The basic-ratelimit policy provides simplified rate limiting by delegating to the core advanced-ratelimit policy. It uses routename/apiname as the rate limit key and transforms simple limits configuration to full quota config.

### Test Coverage Requirements

Create comprehensive unit tests covering:

#### 1. Policy Initialization Tests
- ✅ Test `GetPolicy()` returns non-nil policy
- ✅ Test `GetPolicy()` with valid limits configuration
- ✅ Test `GetPolicy()` with missing limits (should use delegate defaults)
- ✅ Test `Mode()` returns correct processing mode

#### 2. Configuration Transformation Tests
- ✅ Test `transformToRatelimitParams()` creates correct quota structure
- ✅ Test key extraction type is "routename" for operation-level policies
- ✅ Test key extraction type is "apiname" for API-level policies (metadata.AttachedTo == LevelAPI)
- ✅ Test limits array is passed through correctly
- ✅ Test system parameters are passed through (algorithm, backend, redis, memory)

#### 3. Delegation Tests
- ✅ Test OnRequest delegates to advanced-ratelimit policy
- ✅ Test OnResponse delegates to advanced-ratelimit policy
- ✅ Verify delegate policy is called with transformed params

#### 4. System Parameter Pass-Through Tests
- ✅ Test algorithm parameter (gcra, fixedwindow)
- ✅ Test backend parameter (memory, redis)
- ✅ Test redis configuration parameters
- ✅ Test memory configuration parameters

#### 5. Edge Cases
- ✅ Test with empty limits array
- ✅ Test with single limit
- ✅ Test with multiple limits
- ✅ Test with nil params
- ✅ Test attached to API level vs operation level

### Implementation Guidelines

1. Create helper functions:
   ```go
   func createMockMetadata(attachedTo policy.PolicyAttachmentLevel) policy.PolicyMetadata
   func createLimitsConfig(count int) []interface{}
   ```

2. Test structure example:
   ```go
   func TestBasicRateLimitPolicy_TransformParams_RouteName(t *testing.T) {
       metadata := policy.PolicyMetadata{
           AttachedTo: policy.LevelOperation,
           RouteName:  "test-route",
       }
       params := map[string]interface{}{
           "limits": []interface{}{
               map[string]interface{}{
                   "limit":    100,
                   "duration": "1m",
               },
           },
       }
       
       p, err := GetPolicy(metadata, params)
       if err != nil {
           t.Fatalf("Expected no error, got %v", err)
       }
       
       // Verify p.delegate is configured correctly
   }
   ```

3. Mock or verify calls to the delegate policy

4. Test both API-level and operation-level attachment

### Before Submitting PR

```bash
cd gateway/policies/basic-ratelimit/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios listed above are covered
- [ ] Tests pass with `go test -v ./...`
- [ ] Code coverage is >80%
- [ ] Configuration transformation is thoroughly tested
- [ ] Delegation to advanced-ratelimit is verified
- [ ] Both attachment levels are tested
- [ ] System parameters pass-through is validated


---

## Issue 7: Add unit tests for pii-masking-regex policy

**Title:** Add unit tests for pii-masking-regex policy

**Labels:** `testing`, `enhancement`, `policy`, `security`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/pii-masking-regex/v0.1.0/`

### Test File to Create
`gateway/policies/pii-masking-regex/v0.1.0/piimaskingregex_test.go`

### Overview
The pii-masking-regex policy masks or redacts PII (Personally Identifiable Information) in request/response bodies using regex patterns. It supports JSONPath extraction, masking with placeholders, and restoration in responses.

### Test Coverage Requirements

#### 1. Policy Initialization Tests
- ✅ Test GetPolicy() with valid piiEntities
- ✅ Test GetPolicy() with missing piiEntities (should return error)
- ✅ Test GetPolicy() with invalid piiEntity names (must match ^[A-Z_]+$)
- ✅ Test GetPolicy() with invalid regex patterns
- ✅ Test GetPolicy() with duplicate piiEntity names (should return error)
- ✅ Test GetPolicy() with empty piiEntities array (should return error)
- ✅ Test Mode() returns BodyModeBuffer for both request and response

#### 2. Request Masking Tests (Masking Mode, redactPII=false)
- ✅ Test masking EMAIL patterns
- ✅ Test masking PHONE patterns
- ✅ Test masking SSN patterns
- ✅ Test masking multiple PII entities in same content
- ✅ Test masking with JSONPath extraction
- ✅ Test masking without JSONPath (whole payload)
- ✅ Verify masked content uses placeholders like [EMAIL_0000]
- ✅ Verify PII mappings stored in metadata
- ✅ Verify UpstreamRequestModifications with modified body

#### 3. Request Redaction Tests (Redaction Mode, redactPII=true)
- ✅ Test redacting EMAIL patterns (replaced with *****)
- ✅ Test redacting multiple PII entities
- ✅ Test redacting with JSONPath
- ✅ Verify no metadata is stored (no restoration needed)

#### 4. Response Restoration Tests (Masking Mode only)
- ✅ Test restoration of masked PII from metadata
- ✅ Test restoration of multiple masked entities
- ✅ Test restoration with no metadata (pass-through)
- ✅ Test restoration when redactPII=true (should not restore)
- ✅ Verify UpstreamResponseModifications with restored body

#### 5. JSONPath Tests
- ✅ Test with empty jsonPath (processes entire payload)
- ✅ Test with specific jsonPath (e.g., "$.content")
- ✅ Test with nested jsonPath (e.g., "$.data.message")
- ✅ Test with invalid jsonPath (should return error)

#### 6. Edge Cases
- ✅ Test with empty request body
- ✅ Test with nil request body
- ✅ Test with non-JSON content
- ✅ Test with content containing no PII
- ✅ Test with content containing only PII
- ✅ Test with overlapping regex patterns
- ✅ Test with already masked content (should not re-mask placeholders)

#### 7. Error Handling
- ✅ Test error response format (JSON with code and message)
- ✅ Test JSONPath extraction errors
- ✅ Test handling of malformed JSON

### Implementation Guidelines

1. Create test patterns:
   ```go
   var testPIIPatterns = map[string]string{
       "EMAIL": `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
       "PHONE": `\b\d{3}-\d{3}-\d{4}\b`,
       "SSN":   `\b\d{3}-\d{2}-\d{4}\b`,
   }
   ```

2. Helper functions:
   ```go
   func createPIIEntitiesParam(patterns map[string]string) []interface{}
   func createRequestWithBody(body string) *policy.RequestContext
   func createResponseWithBody(body string, metadata map[string]interface{}) *policy.ResponseContext
   ```

3. Test both masking and redaction modes thoroughly

### Before Submitting PR

```bash
cd gateway/policies/pii-masking-regex/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios covered
- [ ] Tests pass
- [ ] Coverage >80%
- [ ] Both masking and redaction modes tested
- [ ] JSONPath extraction tested
- [ ] Response restoration tested

---

## Issue 8: Add unit tests for word-count-guardrail policy

**Title:** Add unit tests for word-count-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/word-count-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/word-count-guardrail/v0.1.0/wordcountguardrail_test.go`

### Overview
Word count guardrail validates that text content contains a word count within configured min/max boundaries, supporting both request and response validation with invert mode.

### Test Coverage Requirements

#### 1. Policy Initialization Tests
- ✅ Test GetPolicy() with valid request params
- ✅ Test GetPolicy() with valid response params
- ✅ Test GetPolicy() with both request and response params
- ✅ Test GetPolicy() with neither (should return error)
- ✅ Test GetPolicy() with missing min/max (should return error)
- ✅ Test GetPolicy() with min > max (should return error)
- ✅ Test GetPolicy() with negative min (should return error)
- ✅ Test GetPolicy() with zero or negative max (should return error)

#### 2. Request Validation Tests - Normal Mode (invert=false)
- ✅ Test word count within range [min, max] - should pass
- ✅ Test word count below min - should fail
- ✅ Test word count above max - should fail
- ✅ Test word count exactly at min boundary - should pass
- ✅ Test word count exactly at max boundary - should pass
- ✅ Verify ImmediateResponse with status 422 on failure

#### 3. Request Validation Tests - Invert Mode (invert=true)
- ✅ Test word count within range [min, max] - should fail
- ✅ Test word count below min - should pass
- ✅ Test word count above max - should pass

#### 4. Response Validation Tests
- ✅ Test response word count validation (normal mode)
- ✅ Test response word count validation (invert mode)
- ✅ Verify UpstreamResponseModifications with modified status and body on failure

#### 5. JSONPath Tests
- ✅ Test with empty jsonPath (whole payload)
- ✅ Test with specific jsonPath extraction
- ✅ Test with invalid jsonPath (should return error)

#### 6. ShowAssessment Tests
- ✅ Test showAssessment=true includes assessment details in error
- ✅ Test showAssessment=false excludes assessment details
- ✅ Verify assessment message format

#### 7. Word Counting Edge Cases
- ✅ Test with empty content (0 words)
- ✅ Test with single word
- ✅ Test with multiple spaces between words
- ✅ Test with newlines and tabs
- ✅ Test with punctuation
- ✅ Test with Unicode characters
- ✅ Test with leading/trailing whitespace

#### 8. Parameter Extraction Tests
- ✅ Test extractInt() with int type
- ✅ Test extractInt() with float64 type
- ✅ Test extractInt() with string type
- ✅ Test extractInt() with invalid types

### Implementation Guidelines

1. Helper functions:
   ```go
   func createWordCountParams(min, max int, invert, showAssessment bool, jsonPath string) map[string]interface{}
   func createRequestWithContent(content string) *policy.RequestContext
   ```

2. Test word counting algorithm matches regex: `\\s+`

### Before Submitting PR

```bash
cd gateway/policies/word-count-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios covered
- [ ] Tests pass
- [ ] Coverage >80%
- [ ] Both normal and invert modes tested
- [ ] Request and response phases tested
- [ ] Word counting edge cases covered

---

## Issue 9: Add unit tests for sentence-count-guardrail policy

**Title:** Add unit tests for sentence-count-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/sentence-count-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/sentence-count-guardrail/v0.1.0/sentencecountguardrail_test.go`

### Overview
Similar to word-count-guardrail but validates sentence count using sentence-terminating punctuation (., !, ?).

### Test Coverage Requirements

#### Policy Initialization, Validation, and Edge Cases
- ✅ Similar structure to word-count-guardrail
- ✅ Test sentence detection with period (.)
- ✅ Test sentence detection with exclamation mark (!)
- ✅ Test sentence detection with question mark (?)
- ✅ Test multiple sentences
- ✅ Test sentences with abbreviations (Dr., Mr., etc.)
- ✅ Test empty content (0 sentences)
- ✅ Test content without sentence terminators
- ✅ Test with newlines between sentences
- ✅ Test normal and invert modes
- ✅ Test request and response phases
- ✅ Test showAssessment parameter
- ✅ Test JSONPath extraction

### Implementation Guidelines
- Follow same pattern as word-count-guardrail
- Focus on sentence detection regex testing

### Before Submitting PR
```bash
cd gateway/policies/sentence-count-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All scenarios covered
- [ ] Sentence counting algorithm thoroughly tested
- [ ] Coverage >80%

---

## Issue 10: Add unit tests for content-length-guardrail policy

**Title:** Add unit tests for content-length-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/content-length-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/content-length-guardrail/v0.1.0/contentlengthguardrail_test.go`

### Overview
Validates content length (character/byte count) is within min/max boundaries.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid params
- ✅ Test with missing min/max (error)
- ✅ Test with min > max (error)
- ✅ Test with negative values (error)

#### Length Validation
- ✅ Test content length within range
- ✅ Test content length below min
- ✅ Test content length above max
- ✅ Test exactly at boundaries
- ✅ Test with empty content
- ✅ Test with Unicode characters (multi-byte)
- ✅ Test normal and invert modes
- ✅ Test request and response phases
- ✅ Test showAssessment parameter
- ✅ Test JSONPath extraction

### Implementation Guidelines
- Similar to word-count-guardrail
- Focus on character/byte counting

### Before Submitting PR
```bash
cd gateway/policies/content-length-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All scenarios covered
- [ ] Unicode handling tested
- [ ] Coverage >80%

---

## Issue 11: Add unit tests for regex-guardrail policy

**Title:** Add unit tests for regex-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/regex-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/regex-guardrail/v0.1.0/regexguardrail_test.go`

### Overview
Validates content against configured regex patterns, supporting allow/deny lists and invert mode.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid patterns
- ✅ Test with invalid regex patterns (error)
- ✅ Test with empty patterns array (error)
- ✅ Test with both allowPatterns and denyPatterns

#### Pattern Matching - Allow Mode
- ✅ Test content matching allow patterns (pass)
- ✅ Test content not matching allow patterns (fail)
- ✅ Test with multiple allow patterns (any match)

#### Pattern Matching - Deny Mode
- ✅ Test content matching deny patterns (fail)
- ✅ Test content not matching deny patterns (pass)
- ✅ Test with multiple deny patterns (any match triggers deny)

#### Invert Mode
- ✅ Test invert with allow patterns
- ✅ Test invert with deny patterns

#### Edge Cases
- ✅ Test with empty content
- ✅ Test with special regex characters
- ✅ Test with complex patterns
- ✅ Test with multiline patterns
- ✅ Test request and response phases
- ✅ Test showAssessment parameter
- ✅ Test JSONPath extraction

### Implementation Guidelines
- Test regex compilation and matching
- Test allow/deny logic carefully

### Before Submitting PR
```bash
cd gateway/policies/regex-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All scenarios covered
- [ ] Regex patterns thoroughly tested
- [ ] Coverage >80%

---

## Issue 12: Add unit tests for url-guardrail policy

**Title:** Add unit tests for url-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/url-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/url-guardrail/v0.1.0/urlguardrail_test.go`

### Overview
Detects and validates URLs in content against allow/deny lists, supporting protocol filtering and invert mode.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid params
- ✅ Test with allowedProtocols (http, https, ftp, etc.)
- ✅ Test with deniedProtocols

#### URL Detection
- ✅ Test detection of http:// URLs
- ✅ Test detection of https:// URLs
- ✅ Test detection of ftp:// URLs
- ✅ Test detection of multiple URLs in content
- ✅ Test URL extraction from text

#### Allow/Deny Lists
- ✅ Test URLs matching allow list (pass)
- ✅ Test URLs not matching allow list (fail)
- ✅ Test URLs matching deny list (fail)
- ✅ Test URLs not matching deny list (pass)
- ✅ Test domain matching
- ✅ Test wildcard patterns

#### Protocol Filtering
- ✅ Test allowedProtocols enforcement
- ✅ Test deniedProtocols enforcement

#### Edge Cases
- ✅ Test content with no URLs
- ✅ Test malformed URLs
- ✅ Test URLs with query parameters
- ✅ Test URLs with fragments
- ✅ Test international domain names
- ✅ Test request and response phases
- ✅ Test showAssessment parameter
- ✅ Test JSONPath extraction

### Implementation Guidelines
- Test URL detection regex
- Test protocol and domain filtering

### Before Submitting PR
```bash
cd gateway/policies/url-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All scenarios covered
- [ ] URL detection thoroughly tested
- [ ] Coverage >80%


---

## Issue 13: Add unit tests for json-schema-guardrail policy

**Title:** Add unit tests for json-schema-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`

**Description:**

### Policy Location
`gateway/policies/json-schema-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/json-schema-guardrail/v0.1.0/jsonschemaguardrail_test.go`

### Overview
Validates JSON content against configured JSON Schema, supporting both request and response validation.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid JSON Schema
- ✅ Test with invalid JSON Schema (error)
- ✅ Test with missing schema (error)

#### Schema Validation - Request
- ✅ Test valid JSON against schema (pass)
- ✅ Test invalid JSON against schema (fail)
- ✅ Test with missing required fields
- ✅ Test with wrong data types
- ✅ Test with additional properties (if not allowed)
- ✅ Test with nested objects
- ✅ Test with arrays

#### Schema Validation - Response
- ✅ Test response validation
- ✅ Test validation errors in response phase

#### Edge Cases
- ✅ Test with empty JSON object
- ✅ Test with null values
- ✅ Test with complex nested schemas
- ✅ Test JSONPath extraction
- ✅ Test showAssessment parameter

### Implementation Guidelines
- Use JSON Schema validation library
- Test various schema constraints (required, type, pattern, etc.)

### Before Submitting PR
```bash
cd gateway/policies/json-schema-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Schema validation thoroughly tested
- [ ] Various schema types covered
- [ ] Coverage >80%

---

## Issue 14: Add unit tests for prompt-template policy

**Title:** Add unit tests for prompt-template policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`

**Description:**

### Policy Location
`gateway/policies/prompt-template/v0.1.0/`

### Test File to Create
`gateway/policies/prompt-template/v0.1.0/prompttemplate_test.go`

### Overview
Applies template transformations to prompts, supporting variable substitution and formatting.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid template
- ✅ Test with missing template (error)
- ✅ Test with invalid template syntax

#### Template Application
- ✅ Test simple variable substitution
- ✅ Test multiple variables
- ✅ Test nested templates
- ✅ Test with missing variables
- ✅ Test with conditional logic (if supported)
- ✅ Test with default values

#### Edge Cases
- ✅ Test with empty template
- ✅ Test with special characters in variables
- ✅ Test with Unicode in templates
- ✅ Test JSONPath extraction
- ✅ Test request body modification

### Implementation Guidelines
- Test template rendering engine
- Test variable extraction and substitution

### Before Submitting PR
```bash
cd gateway/policies/prompt-template/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Template processing tested
- [ ] Variable substitution covered
- [ ] Coverage >80%

---

## Issue 15: Add unit tests for prompt-decorator policy

**Title:** Add unit tests for prompt-decorator policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`

**Description:**

### Policy Location
`gateway/policies/prompt-decorator/v0.1.0/`

### Test File to Create
`gateway/policies/prompt-decorator/v0.1.0/promptdecorator_test.go`

### Overview
Adds prefix/suffix/wrapper content to prompts for enhanced context or formatting.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid params
- ✅ Test with prefix only
- ✅ Test with suffix only
- ✅ Test with both prefix and suffix
- ✅ Test with wrapper templates

#### Decoration Application
- ✅ Test prefix addition
- ✅ Test suffix addition
- ✅ Test combined prefix+suffix
- ✅ Test with empty original content
- ✅ Test with multiline content
- ✅ Test preservation of original content

#### Edge Cases
- ✅ Test with empty prefix/suffix
- ✅ Test with special characters
- ✅ Test with Unicode
- ✅ Test JSONPath extraction
- ✅ Test request body modification

### Implementation Guidelines
- Test decoration logic
- Verify original content is preserved

### Before Submitting PR
```bash
cd gateway/policies/prompt-decorator/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Decoration scenarios covered
- [ ] Content preservation verified
- [ ] Coverage >80%

---

## Issue 16: Add unit tests for semantic-prompt-guard policy

**Title:** Add unit tests for semantic-prompt-guard policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`, `security`

**Description:**

### Policy Location
`gateway/policies/semantic-prompt-guard/v0.1.0/`

### Test File to Create
`gateway/policies/semantic-prompt-guard/v0.1.0/semanticpromptguard_test.go`

### Overview
Detects and blocks prompt injection attacks and jailbreak attempts using semantic analysis.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid params
- ✅ Test with detection threshold configuration
- ✅ Test with different sensitivity levels

#### Prompt Injection Detection
- ✅ Test benign prompts (pass)
- ✅ Test obvious injection attempts (fail)
- ✅ Test jailbreak attempts (fail)
- ✅ Test instruction override attempts (fail)
- ✅ Test role-playing injection (fail)

#### Edge Cases
- ✅ Test with empty prompts
- ✅ Test with long prompts
- ✅ Test with multiple languages
- ✅ Test false positive scenarios
- ✅ Test JSONPath extraction
- ✅ Test showAssessment parameter

### Implementation Guidelines
- Mock semantic analysis service if external
- Test detection accuracy

### Before Submitting PR
```bash
cd gateway/policies/semantic-prompt-guard/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Detection scenarios covered
- [ ] Various attack patterns tested
- [ ] Coverage >80%

---

## Issue 17: Add unit tests for semantic-cache policy

**Title:** Add unit tests for semantic-cache policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `caching`

**Description:**

### Policy Location
`gateway/policies/semantic-cache/v0.1.0/`

### Test File to Create
`gateway/policies/semantic-cache/v0.1.0/semanticcache_test.go`

### Overview
Caches responses based on semantic similarity of prompts, reducing redundant AI model calls.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid params
- ✅ Test with cache configuration (TTL, size limits)
- ✅ Test with similarity threshold

#### Cache Operations - Request Phase
- ✅ Test cache miss (no similar prompt cached)
- ✅ Test cache hit (similar prompt found)
- ✅ Test similarity threshold enforcement
- ✅ Test cache key generation
- ✅ Test JSONPath extraction for prompt

#### Cache Operations - Response Phase
- ✅ Test cache storage on response
- ✅ Test TTL enforcement
- ✅ Test cache eviction

#### Edge Cases
- ✅ Test with empty cache
- ✅ Test with cache full scenario
- ✅ Test with identical prompts
- ✅ Test with similar but not identical prompts
- ✅ Test cache invalidation

### Implementation Guidelines
- Mock cache backend
- Test similarity calculation

### Before Submitting PR
```bash
cd gateway/policies/semantic-cache/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Cache hit/miss scenarios covered
- [ ] Similarity matching tested
- [ ] Coverage >80%

---

## Issue 18: Add unit tests for model-round-robin policy

**Title:** Add unit tests for model-round-robin policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `load-balancing`

**Description:**

### Policy Location
`gateway/policies/model-round-robin/v0.1.0/`

### Test File to Create
`gateway/policies/model-round-robin/v0.1.0/roundrobin_test.go`

### Overview
Distributes requests across multiple AI models using round-robin algorithm for load balancing.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid model list
- ✅ Test with empty model list (error)
- ✅ Test with single model
- ✅ Test with multiple models

#### Round-Robin Selection
- ✅ Test first request selects first model
- ✅ Test second request selects second model
- ✅ Test wraparound after last model
- ✅ Test consistent round-robin order
- ✅ Test concurrent request handling
- ✅ Test model selection metadata

#### Request Routing
- ✅ Test request header/body modification for selected model
- ✅ Test model endpoint routing
- ✅ Test UpstreamRequestModifications

#### Edge Cases
- ✅ Test with 2 models (simple case)
- ✅ Test with many models (10+)
- ✅ Test counter overflow
- ✅ Test thread safety

### Implementation Guidelines
- Test round-robin counter state
- Test concurrency if policy maintains state

### Before Submitting PR
```bash
cd gateway/policies/model-round-robin/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Round-robin algorithm verified
- [ ] Model selection tested
- [ ] Coverage >80%

---

## Issue 19: Add unit tests for model-weighted-round-robin policy

**Title:** Add unit tests for model-weighted-round-robin policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `load-balancing`

**Description:**

### Policy Location
`gateway/policies/model-weighted-round-robin/v0.1.0/`

### Test File to Create
`gateway/policies/model-weighted-round-robin/v0.1.0/weightedroundrobin_test.go`

### Overview
Distributes requests across models using weighted round-robin, allowing proportional traffic distribution based on weights.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid models and weights
- ✅ Test with missing weights (error)
- ✅ Test with invalid weights (negative, zero)
- ✅ Test with mismatched models/weights count (error)
- ✅ Test weight normalization

#### Weighted Selection
- ✅ Test distribution matches weights (e.g., [2, 1] = 2/3 and 1/3)
- ✅ Test with equal weights (should be like round-robin)
- ✅ Test with very different weights (e.g., [100, 1])
- ✅ Test selection pattern over many requests
- ✅ Test cumulative weight calculation

#### Request Routing
- ✅ Test request routing to selected model
- ✅ Test model metadata in context

#### Edge Cases
- ✅ Test with single model (weight=1)
- ✅ Test with fractional weights
- ✅ Test concurrent requests
- ✅ Test counter reset/overflow

### Implementation Guidelines
- Test weighted selection algorithm
- Verify distribution over many iterations

### Before Submitting PR
```bash
cd gateway/policies/model-weighted-round-robin/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Weighted algorithm verified
- [ ] Distribution matches weights
- [ ] Coverage >80%

---

## Issue 20: Add unit tests for aws-bedrock-guardrail policy

**Title:** Add unit tests for aws-bedrock-guardrail policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`, `aws`

**Description:**

### Policy Location
`gateway/policies/aws-bedrock-guardrail/v0.1.0/`

### Test File to Create
`gateway/policies/aws-bedrock-guardrail/v0.1.0/awsbedrockguardrail_test.go`

### Overview
Integrates with AWS Bedrock Guardrails API for content filtering, PII detection, and toxicity detection.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid AWS credentials
- ✅ Test with missing credentials (error)
- ✅ Test with guardrail ID configuration
- ✅ Test with region configuration

#### Guardrail Invocation - Request Phase
- ✅ Test safe content (pass)
- ✅ Test unsafe content (fail)
- ✅ Test PII detection
- ✅ Test toxicity detection
- ✅ Test prompt attack detection

#### Response Handling
- ✅ Test guardrail pass response
- ✅ Test guardrail block response
- ✅ Test error handling from AWS API
- ✅ Test timeout handling

#### Edge Cases
- ✅ Test with empty content
- ✅ Test with very long content
- ✅ Test JSONPath extraction
- ✅ Test request and response phases
- ✅ Test showAssessment parameter

### Implementation Guidelines
- Mock AWS Bedrock API calls
- Test API error handling

### Before Submitting PR
```bash
cd gateway/policies/aws-bedrock-guardrail/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] AWS API integration tested
- [ ] Various content types covered
- [ ] Coverage >80%

---

## Issue 21: Add unit tests for azure-content-safety-content-moderation policy

**Title:** Add unit tests for azure-content-safety-content-moderation policy

**Labels:** `testing`, `enhancement`, `policy`, `ai`, `guardrail`, `azure`

**Description:**

### Policy Location
`gateway/policies/azure-content-safety-content-moderation/v0.1.0/`

### Test File to Create
`gateway/policies/azure-content-safety-content-moderation/v0.1.0/azurecontentsafetycontentmoderation_test.go`

### Overview
Integrates with Azure Content Safety API for content moderation, detecting hate, violence, self-harm, and sexual content.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid Azure credentials
- ✅ Test with missing credentials (error)
- ✅ Test with endpoint configuration
- ✅ Test with severity threshold configuration

#### Content Moderation - Request Phase
- ✅ Test safe content (pass)
- ✅ Test hate content detection (fail)
- ✅ Test violence content detection (fail)
- ✅ Test self-harm content detection (fail)
- ✅ Test sexual content detection (fail)
- ✅ Test severity levels (low, medium, high)

#### Response Handling
- ✅ Test moderation pass response
- ✅ Test moderation block response with details
- ✅ Test error handling from Azure API
- ✅ Test timeout handling

#### Edge Cases
- ✅ Test with empty content
- ✅ Test with non-English content
- ✅ Test JSONPath extraction
- ✅ Test request and response phases
- ✅ Test showAssessment parameter

### Implementation Guidelines
- Mock Azure Content Safety API
- Test severity threshold enforcement

### Before Submitting PR
```bash
cd gateway/policies/azure-content-safety-content-moderation/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] Azure API integration tested
- [ ] Content categories covered
- [ ] Coverage >80%

---

## Issue 22: Add unit tests for advanced-ratelimit policy (main logic)

**Title:** Add unit tests for advanced-ratelimit policy (main logic)

**Labels:** `testing`, `enhancement`, `policy`, `ratelimit`

**Description:**

### Policy Location
`gateway/policies/advanced-ratelimit/v0.1.0/`

### Test File to Create
`gateway/policies/advanced-ratelimit/v0.1.0/ratelimit_test.go`

### Overview
Advanced rate limiting with quota management, cost extraction, and multiple backend support (memory, Redis). Note: Algorithm implementations (GCRA, Fixed Window) already have tests.

### Test Coverage Requirements

#### Policy Initialization
- ✅ Test GetPolicy() with valid quotas config
- ✅ Test with missing quotas (error)
- ✅ Test with memory backend
- ✅ Test with Redis backend
- ✅ Test Redis connection configuration
- ✅ Test quota parsing and validation

#### Key Extraction
- ✅ Test routename key extraction
- ✅ Test apiname key extraction
- ✅ Test apiversion key extraction
- ✅ Test IP address extraction
- ✅ Test header-based key extraction
- ✅ Test metadata-based key extraction
- ✅ Test composite keys (multiple components)

#### Cost Extraction
- ✅ Test default cost (1)
- ✅ Test fixed cost
- ✅ Test cost from request header
- ✅ Test cost from response header
- ✅ Test cost from JSONPath in request body
- ✅ Test cost from JSONPath in response body

#### Quota Management
- ✅ Test single quota enforcement
- ✅ Test multiple quotas (all must pass)
- ✅ Test quota with different limits
- ✅ Test quota key generation
- ✅ Test quota caching for memory backend

#### Rate Limit Exceeded
- ✅ Test ImmediateResponse when limit exceeded
- ✅ Test status code customization
- ✅ Test response body customization
- ✅ Test response format (JSON, plain)

#### Response Headers
- ✅ Test X-RateLimit-Limit header (includeXRL=true)
- ✅ Test X-RateLimit-Remaining header
- ✅ Test X-RateLimit-Reset header
- ✅ Test IETF standard headers (includeIETF=true)
- ✅ Test Retry-After header (includeRetry=true)
- ✅ Test header omission when flags are false

#### Redis Backend
- ✅ Test Redis connection initialization
- ✅ Test Redis failopen mode (continue on Redis error)
- ✅ Test Redis failclose mode (block on Redis error)
- ✅ Test Redis authentication
- ✅ Test Redis TLS configuration

#### Memory Backend
- ✅ Test memory limiter caching
- ✅ Test memory limiter state preservation

#### Edge Cases
- ✅ Test with burst parameter
- ✅ Test with multiple limits in single quota
- ✅ Test concurrent requests (thread safety)
- ✅ Test limiter cache eviction
- ✅ Test with invalid cost values

### Implementation Guidelines

1. Mock Redis client for Redis backend tests
2. Test limiter factory and initialization
3. Test quota runtime configuration
4. Helper functions:
   ```go
   func createQuotaConfig(limits []interface{}, keyExtraction []interface{}) map[string]interface{}
   func createMemoryBackendConfig() map[string]interface{}
   func createRedisBackendConfig() map[string]interface{}
   func mockRedisClient() *redis.Client
   ```

### Before Submitting PR
```bash
cd gateway/policies/advanced-ratelimit/v0.1.0
go test -v ./...
go test -v -cover ./...
```

### Acceptance Criteria
- [ ] All test scenarios covered
- [ ] Tests pass
- [ ] Coverage >80%
- [ ] Key extraction thoroughly tested
- [ ] Cost extraction tested for all sources
- [ ] Both memory and Redis backends tested
- [ ] Response headers validated
- [ ] Quota management tested

---

## PR Checklist Template

When submitting your PR for any of these policies, include this checklist:

- [ ] All tests pass: `go test -v ./...`
- [ ] Code coverage >80%: `go test -v -cover ./...`
- [ ] Test file follows naming convention: `<policyname>_test.go`
- [ ] Tests follow patterns from jwt-auth and mcp-auth examples
- [ ] All test functions are named `Test<PolicyName>_<Scenario>`
- [ ] Helper functions are documented with comments
- [ ] Edge cases are covered
- [ ] Error handling is tested
- [ ] Mock dependencies are properly isolated
- [ ] No external service dependencies in unit tests
- [ ] Tests are deterministic (no flaky tests)
- [ ] Code is formatted with `go fmt`
- [ ] Comments explain complex test logic

---

## Getting Help

If you have questions while implementing tests:

1. Review the reference test files (jwt-auth, mcp-auth)
2. Check the policy implementation to understand its behavior
3. Look at Go's testing package documentation
4. Ask in PR comments or create a discussion

---

## Additional Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Go Test Coverage](https://go.dev/blog/cover)
- [Table-Driven Tests in Go](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)
- WSO2 API Platform SDK: `github.com/wso2/api-platform/sdk/gateway/policy/v1alpha`

