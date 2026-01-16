# Gateway Policy Unit Testing Initiative

This repository contains comprehensive documentation and templates for creating unit tests for gateway policies that currently lack test coverage.

## 📋 Overview

Out of 25 gateway policies in `gateway/policies/`, only 3 have unit tests. This initiative provides structured templates to create GitHub issues for implementing tests for the remaining 22 policies.

**Current Status:**
- ✅ **Policies with tests:** 3 (12%)
- ❌ **Policies needing tests:** 22 (88%)
- 🎯 **Target:** 100% coverage with >80% code coverage per policy

## 📚 Documentation Files

### 1. [UNIT_TEST_ISSUES.md](./UNIT_TEST_ISSUES.md)
**Purpose:** Ready-to-use GitHub issue templates for all 22 policies

**What's included:**
- 22 detailed issue templates (one per policy)
- Test coverage requirements specific to each policy
- Implementation guidelines with code patterns
- Commands to run before PR submission
- Acceptance criteria for each policy

**Size:** 1,930 lines | 59KB

**How to use:** Copy a policy's issue template and paste into a new GitHub issue.

### 2. [HOW_TO_CREATE_ISSUES.md](./HOW_TO_CREATE_ISSUES.md)
**Purpose:** Step-by-step guide for creating and managing issues

**What's included:**
- Instructions for using the issue templates
- Complete list of 22 policies needing tests
- GitHub CLI examples for automation
- Test implementation patterns
- Progress tracking guidance

**Size:** 134 lines | 4.7KB

**How to use:** Follow this guide when creating issues from templates.

### 3. [POLICY_TEST_STATUS.md](./POLICY_TEST_STATUS.md)
**Purpose:** Test coverage status and tracking

**What's included:**
- Overview table: status of all 25 policies
- Detailed status by policy with categories
- Priority recommendations (High/Medium)
- Suggested testing phases (1-5)
- Progress tracking framework

**Size:** 212 lines | 6KB

**How to use:** Track progress as tests are implemented and update this document.

## 🚀 Quick Start

### For Issue Creators

1. Open [UNIT_TEST_ISSUES.md](./UNIT_TEST_ISSUES.md)
2. Find the policy you want to create an issue for
3. Copy the entire issue section (from "### Issue N:" to "---")
4. Create a new GitHub issue at: https://github.com/Tharsanan1/api-platform/issues/new
5. Paste the template and add appropriate labels

### For Test Implementers

1. Pick an assigned issue from the repository
2. Review the reference test files:
   - `gateway/policies/jwt-auth/v0.1.0/jwtauth_test.go`
   - `gateway/policies/mcp-auth/v0.1.0/mcp-auth_test.go`
3. Create test file: `gateway/policies/<policy-name>/v0.1.0/<policy>_test.go`
4. Implement tests following the coverage requirements in the issue
5. Run tests locally:
   ```bash
   cd gateway/policies/<policy-name>/v0.1.0
   go test -v ./...
   go test -v -cover ./...
   ```
6. Submit PR with test coverage results (aim for >80%)

## 📊 Policies by Category

### 🔐 Authentication & Authorization
- ✅ jwt-auth (has tests)
- ✅ mcp-auth (has tests)
- ❌ api-key-auth (Issue 1)
- ❌ basic-auth (Issue 2)

### 🛡️ Security
- ❌ cors (Issue 4)
- ❌ pii-masking-regex (Issue 13)

### ⏱️ Rate Limiting
- ⚠️ advanced-ratelimit (algorithms tested, main needs tests - Issue 22)
- ❌ basic-ratelimit (Issue 3)

### 🛑 Content Guardrails
- ❌ content-length-guardrail (Issue 7)
- ❌ word-count-guardrail (Issue 8)
- ❌ sentence-count-guardrail (Issue 9)
- ❌ regex-guardrail (Issue 10)
- ❌ url-guardrail (Issue 11)
- ❌ json-schema-guardrail (Issue 12)

### 🤖 AI & Machine Learning
**Prompt Management:**
- ❌ prompt-template (Issue 15)
- ❌ prompt-decorator (Issue 16)

**AI Safety & Security:**
- ❌ semantic-prompt-guard (Issue 14)
- ❌ aws-bedrock-guardrail (Issue 21)
- ❌ azure-content-safety-content-moderation (Issue 20)

**AI Infrastructure:**
- ❌ semantic-cache (Issue 17)
- ❌ model-round-robin (Issue 18)
- ❌ model-weighted-round-robin (Issue 19)

### 📝 Headers & Response
- ❌ modify-headers (Issue 5)
- ❌ respond (Issue 6)

## 🎯 Recommended Testing Order

### Phase 1: Core Security & Auth (High Priority)
1. api-key-auth
2. basic-auth
3. cors
4. pii-masking-regex

### Phase 2: Rate Limiting (High Priority)
5. basic-ratelimit
6. advanced-ratelimit (main logic)

### Phase 3: Basic Features (Medium Priority)
7. modify-headers
8. respond

### Phase 4: Content Guardrails (Medium Priority)
9-14. All guardrails (content-length, word-count, sentence-count, regex, url, json-schema)

### Phase 5: AI Features (Use Case Specific)
15-22. All AI-related policies (prompts, security, infrastructure)

## 📋 Testing Standards

All unit tests must meet these standards:

- ✅ **Coverage:** Minimum 80% code coverage
- ✅ **Scope:** Test happy path, error cases, and edge cases
- ✅ **Independence:** Tests can run in parallel
- ✅ **Clarity:** Test names clearly describe what they test
- ✅ **Documentation:** Include comments for complex test scenarios
- ✅ **Patterns:** Follow patterns from jwt-auth and mcp-auth tests

### Required Test Commands

Before submitting PR, run:

```bash
cd gateway/policies/<policy-name>/v0.1.0

# Run tests with verbose output
go test -v ./...

# Check coverage
go test -v -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run with race detector
go test -v -race ./...
```

## 🔄 Progress Tracking

Use [POLICY_TEST_STATUS.md](./POLICY_TEST_STATUS.md) to track:

- [ ] Issues created (0/22)
- [ ] Issues assigned (0/22)
- [ ] PRs submitted (0/22)
- [ ] PRs merged (0/22)
- [ ] Overall coverage: 12% → Target: 100%

Update the status document when:
- ✅ A policy's tests are merged
- 📊 Coverage metrics change significantly
- 🎯 Milestones are reached

## 🤝 Contributing

### Creating Issues

1. Review [HOW_TO_CREATE_ISSUES.md](./HOW_TO_CREATE_ISSUES.md)
2. Use templates from [UNIT_TEST_ISSUES.md](./UNIT_TEST_ISSUES.md)
3. Add appropriate labels: `testing`, `enhancement`, `policy`, etc.
4. Assign based on team expertise

### Implementing Tests

1. Review existing test files for patterns
2. Follow the test coverage requirements in your assigned issue
3. Ensure >80% code coverage
4. Run all test commands before submitting PR
5. Include coverage metrics in PR description

### Reviewing PRs

Check that:
- [ ] All tests pass
- [ ] Coverage is >80%
- [ ] Tests follow established patterns
- [ ] Test names are descriptive
- [ ] Edge cases are covered
- [ ] Tests are independent

## 📖 Reference Materials

### Example Test Files
- `gateway/policies/jwt-auth/v0.1.0/jwtauth_test.go` - Comprehensive authentication tests
- `gateway/policies/mcp-auth/v0.1.0/mcp-auth_test.go` - Delegation pattern tests

### Go Testing Resources
- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Table-Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Testing Best Practices](https://go.dev/doc/effective_go#testing)

### Policy SDK
- `github.com/wso2/api-platform/sdk/gateway/policy/v1alpha`

## 🎉 Success Metrics

Track these metrics to measure success:

| Metric | Current | Target |
|--------|---------|--------|
| Policies with tests | 3 | 25 |
| Coverage % | 12% | 100% |
| Avg code coverage | N/A | >80% |
| Test files | 3 | 25 |

## 📞 Support

### Questions?

- **About templates:** See [UNIT_TEST_ISSUES.md](./UNIT_TEST_ISSUES.md)
- **About implementation:** Check reference tests or ask in PR comments
- **About policies:** Review policy source code in `gateway/policies/<policy>/v0.1.0/`
- **About progress:** See [POLICY_TEST_STATUS.md](./POLICY_TEST_STATUS.md)

### Getting Help

1. Check the three documentation files in this directory
2. Review existing test implementations
3. Ask questions in GitHub issue or PR comments
4. Tag relevant team members for expertise

---

**Last Updated:** 2026-01-16  
**Status:** Documentation complete, ready for issue creation  
**Next Step:** Create GitHub issues using the templates
