# How to Create GitHub Issues for Policy Unit Tests

This guide explains how to use the `UNIT_TEST_ISSUES.md` document to create GitHub issues for implementing unit tests for gateway policies.

## Quick Start

1. **Review the document:** Open `UNIT_TEST_ISSUES.md` to see all 22 policy test issues
2. **Choose a policy:** Select a policy you want to create an issue for
3. **Copy the issue template:** Copy the entire section for that policy (from "### Issue N" to the next "---")
4. **Create GitHub issue:** 
   - Go to https://github.com/Tharsanan1/api-platform/issues/new
   - Paste the template content
   - The title, labels, and description are all included in the template
5. **Add labels:** Apply the labels mentioned in the template (testing, enhancement, policy, etc.)

## Issue Template Structure

Each issue template in `UNIT_TEST_ISSUES.md` contains:

- **Title:** Clear, actionable title
- **Labels:** Suggested labels for categorization
- **Policy Location:** Exact file path
- **Overview:** What the policy does
- **Test Coverage Requirements:** Detailed list of what to test
- **Test File:** Name of the test file to create
- **Implementation Guidelines:** How to structure the tests
- **Before Submitting PR:** Commands to run before submission
- **Acceptance Criteria:** Checklist for completion

## Policies Needing Unit Tests (22)

### Authentication & Security
1. api-key-auth
2. basic-auth
3. cors

### Header & Response Management
4. modify-headers
5. respond

### Rate Limiting
6. basic-ratelimit
7. advanced-ratelimit (main logic)

### Content Guardrails
8. content-length-guardrail
9. word-count-guardrail
10. sentence-count-guardrail
11. regex-guardrail
12. url-guardrail
13. json-schema-guardrail

### Security & PII
14. pii-masking-regex

### AI Guardrails
15. semantic-prompt-guard
16. aws-bedrock-guardrail
17. azure-content-safety-content-moderation

### AI Prompt Management
18. prompt-template
19. prompt-decorator

### AI Infrastructure
20. semantic-cache
21. model-round-robin
22. model-weighted-round-robin

## Creating All Issues at Once

If you want to create all 22 issues, you can:

1. Use GitHub's API (requires authentication)
2. Use GitHub CLI (`gh` tool)
3. Manually create them one by one (recommended for review)

### Using GitHub CLI (if available)

```bash
# Example for creating one issue
gh issue create \
  --title "Add unit tests for api-key-auth policy" \
  --label "testing,enhancement,policy" \
  --body "$(sed -n '/### Issue 1:/,/^---$/p' UNIT_TEST_ISSUES.md)"
```

## For Issue Assignees

When you're assigned to implement tests for a policy:

1. **Read the issue carefully:** Understand all test scenarios required
2. **Review reference tests:** Check `jwt-auth` and `mcp-auth` test files
3. **Create test file:** Follow the naming convention `<policy>_test.go`
4. **Implement tests:** Cover all scenarios from the issue
5. **Run tests locally:**
   ```bash
   cd gateway/policies/<policy-name>/v0.1.0
   go test -v ./...
   go test -v -cover ./...
   ```
6. **Verify coverage:** Aim for >80% code coverage
7. **Submit PR:** Include test results in PR description

## Test Implementation Pattern

Follow this structure in your test files:

```go
package policyname

import (
    "testing"
    policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// Test policy initialization
func TestGetPolicy(t *testing.T) { /* ... */ }

// Test processing mode
func TestMode(t *testing.T) { /* ... */ }

// Test request handling scenarios
func TestOnRequest_ValidCase(t *testing.T) { /* ... */ }
func TestOnRequest_InvalidCase(t *testing.T) { /* ... */ }
func TestOnRequest_EdgeCase(t *testing.T) { /* ... */ }

// Test response handling (if applicable)
func TestOnResponse_ValidCase(t *testing.T) { /* ... */ }

// Helper functions
func createMockRequestContext(headers map[string][]string) *policy.RequestContext {
    return &policy.RequestContext{
        SharedContext: &policy.SharedContext{
            RequestID: "test-request-id",
            Metadata:  make(map[string]any),
        },
        Headers: policy.NewHeaders(headers),
        // ... other fields
    }
}
```

## Questions?

If you have questions about:
- **The issue templates:** Review `UNIT_TEST_ISSUES.md`
- **Test implementation:** Check reference tests in `jwt-auth` and `mcp-auth`
- **Policy behavior:** Read the policy source code in `gateway/policies/<policy>/v0.1.0/`
- **General questions:** Ask in the PR or issue comments

## Progress Tracking

Create a project board or tracking issue to monitor:
- [ ] Issues created (22 total)
- [ ] Issues assigned
- [ ] PRs submitted
- [ ] PRs merged
- [ ] Overall test coverage improvement

Target: 100% of policies have comprehensive unit tests with >80% code coverage.
