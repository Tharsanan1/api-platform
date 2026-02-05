# Gateway Policy Test Coverage Status

This document provides a quick reference for the test coverage status of all gateway policies.

## Test Coverage Summary

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Has Tests | 3 | 12% |
| ❌ Needs Tests | 22 | 88% |
| **Total** | **25** | **100%** |

## Detailed Status by Policy

### Policies WITH Unit Tests ✅

| Policy Name | Test File Location | Notes |
|-------------|-------------------|-------|
| jwt-auth | `gateway/policies/jwt-auth/v0.1.0/jwtauth_test.go` | Comprehensive authentication tests |
| mcp-auth | `gateway/policies/mcp-auth/v0.1.0/mcp-auth_test.go` | MCP authentication tests |
| advanced-ratelimit (algorithms) | `gateway/policies/advanced-ratelimit/v0.1.0/algorithms/*/memory_test.go` | Algorithm-specific tests only |

### Policies NEEDING Unit Tests ❌

| # | Policy Name | Category | Priority | Issue Template |
|---|-------------|----------|----------|----------------|
| 1 | api-key-auth | Authentication | High | Issue 1 in UNIT_TEST_ISSUES.md |
| 2 | basic-auth | Authentication | High | Issue 2 in UNIT_TEST_ISSUES.md |
| 3 | cors | Security | High | Issue 4 in UNIT_TEST_ISSUES.md |
| 4 | basic-ratelimit | Rate Limiting | High | Issue 3 in UNIT_TEST_ISSUES.md |
| 5 | advanced-ratelimit (main) | Rate Limiting | High | Issue 22 in UNIT_TEST_ISSUES.md |
| 6 | modify-headers | Headers | Medium | Issue 5 in UNIT_TEST_ISSUES.md |
| 7 | respond | Response | Medium | Issue 6 in UNIT_TEST_ISSUES.md |
| 8 | content-length-guardrail | Guardrail | Medium | Issue 7 in UNIT_TEST_ISSUES.md |
| 9 | word-count-guardrail | Guardrail | Medium | Issue 8 in UNIT_TEST_ISSUES.md |
| 10 | sentence-count-guardrail | Guardrail | Medium | Issue 9 in UNIT_TEST_ISSUES.md |
| 11 | regex-guardrail | Guardrail | Medium | Issue 10 in UNIT_TEST_ISSUES.md |
| 12 | url-guardrail | Guardrail | Medium | Issue 11 in UNIT_TEST_ISSUES.md |
| 13 | json-schema-guardrail | Guardrail | Medium | Issue 12 in UNIT_TEST_ISSUES.md |
| 14 | pii-masking-regex | Security/PII | High | Issue 13 in UNIT_TEST_ISSUES.md |
| 15 | semantic-prompt-guard | AI/Security | Medium | Issue 14 in UNIT_TEST_ISSUES.md |
| 16 | prompt-template | AI/Prompts | Medium | Issue 15 in UNIT_TEST_ISSUES.md |
| 17 | prompt-decorator | AI/Prompts | Medium | Issue 16 in UNIT_TEST_ISSUES.md |
| 18 | semantic-cache | AI/Cache | Medium | Issue 17 in UNIT_TEST_ISSUES.md |
| 19 | model-round-robin | AI/LB | Medium | Issue 18 in UNIT_TEST_ISSUES.md |
| 20 | model-weighted-round-robin | AI/LB | Medium | Issue 19 in UNIT_TEST_ISSUES.md |
| 21 | azure-content-safety-content-moderation | AI/Security | Medium | Issue 20 in UNIT_TEST_ISSUES.md |
| 22 | aws-bedrock-guardrail | AI/Security | Medium | Issue 21 in UNIT_TEST_ISSUES.md |

## Categories Breakdown

### Authentication & Authorization (3 policies)
- ✅ jwt-auth (has tests)
- ✅ mcp-auth (has tests)
- ❌ api-key-auth (needs tests)
- ❌ basic-auth (needs tests)

### Security (3 policies)
- ❌ cors (needs tests)
- ❌ pii-masking-regex (needs tests)
- Plus: AI security policies (see AI section)

### Rate Limiting (2 policies)
- ⚠️ advanced-ratelimit (algorithms tested, main logic needs tests)
- ❌ basic-ratelimit (needs tests)

### Content Guardrails (6 policies)
- ❌ content-length-guardrail
- ❌ word-count-guardrail
- ❌ sentence-count-guardrail
- ❌ regex-guardrail
- ❌ url-guardrail
- ❌ json-schema-guardrail

### AI & Machine Learning (8 policies)
**Prompt Management:**
- ❌ prompt-template
- ❌ prompt-decorator

**Safety & Security:**
- ❌ semantic-prompt-guard
- ❌ aws-bedrock-guardrail
- ❌ azure-content-safety-content-moderation

**Infrastructure:**
- ❌ semantic-cache
- ❌ model-round-robin
- ❌ model-weighted-round-robin

### Headers & Response (2 policies)
- ❌ modify-headers
- ❌ respond

## Priority Recommendations

### High Priority (Authentication & Core Features)
These policies are fundamental and should be tested first:
1. **api-key-auth** - Common authentication method
2. **basic-auth** - Standard HTTP authentication
3. **cors** - Critical for cross-origin security
4. **pii-masking-regex** - Data privacy protection
5. **basic-ratelimit** - API protection
6. **advanced-ratelimit** - Advanced API protection

### Medium Priority (Feature-Specific)
These policies support specific use cases:
- All guardrails (content validation)
- Header/response manipulation policies
- AI-related policies (if using AI features)

### Testing Order Suggestion

For optimal coverage, implement tests in this order:

**Phase 1: Core Security & Auth** (High Impact)
1. api-key-auth
2. basic-auth
3. cors
4. pii-masking-regex

**Phase 2: Rate Limiting** (High Impact)
5. basic-ratelimit
6. advanced-ratelimit (main logic)

**Phase 3: Basic Features** (Medium Impact)
7. modify-headers
8. respond

**Phase 4: Content Guardrails** (Medium Impact)
9. content-length-guardrail
10. word-count-guardrail
11. sentence-count-guardrail
12. regex-guardrail
13. url-guardrail
14. json-schema-guardrail

**Phase 5: AI Features** (Use Case Specific)
15. prompt-template
16. prompt-decorator
17. semantic-prompt-guard
18. semantic-cache
19. model-round-robin
20. model-weighted-round-robin
21. aws-bedrock-guardrail
22. azure-content-safety-content-moderation

## How to Track Progress

1. **Create GitHub Issues:** Use templates from `UNIT_TEST_ISSUES.md`
2. **Assign Issues:** Distribute among team members
3. **Update This Document:** Mark policies as ✅ when tests are merged
4. **Monitor Coverage:** Track overall code coverage metrics

## Target Goals

- **Short-term (1 month):** All High Priority policies have tests
- **Mid-term (2 months):** All Medium Priority policies have tests
- **Long-term (3 months):** 100% of policies have >80% test coverage

## References

- **Issue Templates:** `UNIT_TEST_ISSUES.md`
- **How-to Guide:** `HOW_TO_CREATE_ISSUES.md`
- **Example Tests:** 
  - `gateway/policies/jwt-auth/v0.1.0/jwtauth_test.go`
  - `gateway/policies/mcp-auth/v0.1.0/mcp-auth_test.go`

---

Last Updated: 2026-01-16  
Status: 22 of 25 policies need unit tests (88%)
