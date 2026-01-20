# --------------------------------------------------------------------
# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@budget-ratelimit
Feature: Budget Rate Limiting
  As an API developer
  I want to limit API usage based on monetary cost
  So that I can control spending on LLM API usage

  Background:
    Given the gateway services are running

  Scenario: Basic total budget rate limiting
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-total-api
      spec:
        displayName: Budget RateLimit Total API
        version: v1.0
        context: /budget-ratelimit-total/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  totalBudget:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-total/v1.0/get" to be ready

    # Cost calculation:
    # - Prompt: 1000 tokens × ($10/1M) = $0.01
    # - Completion: 1000 tokens × ($30/1M) = $0.03
    # - Total cost per request: $0.04
    
    # With a limit of 100 units, we can make 2500 requests at $0.04 each
    # Let's use larger token counts for easier verification
    
    # Request with 500,000 prompt tokens + 500,000 completion tokens
    # Prompt cost: 500000 × 0.00001 = $5
    # Completion cost: 500000 × 0.00003 = $15
    # Total cost: $20
    When I send a POST request to "http://localhost:8080/budget-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 500000, "completion_tokens": 500000}}
      """
    Then the response status code should be 200
    # 100 - 20 = 80 remaining
    And the response header "X-RateLimit-Remaining" should be "80"

    # Second request: same cost ($20)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 500000, "completion_tokens": 500000}}
      """
    Then the response status code should be 200
    # 80 - 20 = 60 remaining
    And the response header "X-RateLimit-Remaining" should be "60"

    # Third request: $60 cost (exhausts budget)
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 1666667 × 0.00003 ≈ $50
    When I send a POST request to "http://localhost:8080/budget-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 1666667}}
      """
    Then the response status code should be 200
    # 60 - 60 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Fourth request should be rate limited
    When I send a POST request to "http://localhost:8080/budget-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000, "completion_tokens": 1000}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Separate prompt and completion budgets
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-separate-api
      spec:
        displayName: Budget RateLimit Separate API
        version: v1.0
        context: /budget-ratelimit-separate/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  promptBudget:
                    limits:
                      - limit: 50
                        duration: "1h"
                  completionBudget:
                    limits:
                      - limit: 30
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-separate/v1.0/get" to be ready

    # Test completion budget exhaustion (more restrictive in terms of cost)
    # Prompt budget: $50 limit, Completion budget: $30 limit
    # With 1M completion tokens at $30/1M = $30 cost
    When I send a POST request to "http://localhost:8080/budget-ratelimit-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 1000000}}
      """
    Then the response status code should be 200
    # Prompt cost: 100000 × 0.00001 = $1 (50 - 1 = 49 remaining)
    # Completion cost: 1000000 × 0.00003 = $30 (30 - 30 = 0 remaining, exhausted!)

    # Next request should be blocked by completion budget
    When I send a POST request to "http://localhost:8080/budget-ratelimit-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 10000, "completion_tokens": 10000}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Default value on extraction failure with pricing applied
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-default-api
      spec:
        displayName: Budget RateLimit Default API
        version: v1.0
        context: /budget-ratelimit-default/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  totalBudget:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-default/v1.0/get" to be ready

    # Test basic budget deduction with round numbers
    # Prompt: 10000000 × 0.00001 = $100 (exhausts entire budget)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-default/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 10000000, "completion_tokens": 0}}
      """
    Then the response status code should be 200
    # 100 - 100 = 0 remaining (budget exhausted)

    # Second request should fail (any cost should be blocked)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-default/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 0}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Multiple budget limits (burst and daily)
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-multilimits-api
      spec:
        displayName: Budget RateLimit Multi-Limits API
        version: v1.0
        context: /budget-ratelimit-multilimits/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  totalBudget:
                    limits:
                      - limit: 100
                        duration: "1m"
                      - limit: 50
                        duration: "24h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-multilimits/v1.0/get" to be ready

    # The 24h limit ($50) is more restrictive than the 1m limit ($100)
    # Request with cost = $30
    When I send a POST request to "http://localhost:8080/budget-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 666667}}
      """
    Then the response status code should be 200
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 666667 × 0.00003 ≈ $20
    # Total: $30
    # 1m limit: 100 - 30 = 70 remaining
    # 24h limit: 50 - 30 = 20 remaining

    # Second request with cost = $20 (exhausts 24h limit)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 333334}}
      """
    Then the response status code should be 200
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 333334 × 0.00003 ≈ $10
    # Total: $20
    # 1m limit: 70 - 20 = 50 remaining
    # 24h limit: 20 - 20 = 0 remaining (exhausted!)

    # Third request should be blocked by 24h limit
    When I send a POST request to "http://localhost:8080/budget-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000, "completion_tokens": 1000}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: API-level budget rate limiting
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-api-level-api
      spec:
        displayName: Budget RateLimit API Level
        version: v1.0
        context: /budget-ratelimit-api-level/$version
        upstream:
          main:
            url: http://echo-backend:80
        policies:
          - name: budget-ratelimit
            version: v0.1.0
            params:
              pricing:
                promptTokens:
                  costPer1MTokens: 10.00
                  tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                completionTokens:
                  costPer1MTokens: 30.00
                  tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
              totalBudget:
                limits:
                  - limit: 100
                    duration: "1h"
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything/route1
          - method: POST
            path: /anything/route2
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-api-level/v1.0/get" to be ready

    # API-level policy uses apiname as key - all routes share the same budget
    # Use exact numbers: 5M prompt tokens at $10/1M = $50
    When I send a POST request to "http://localhost:8080/budget-ratelimit-api-level/v1.0/anything/route1" with body:
      """
      {"usage": {"prompt_tokens": 5000000, "completion_tokens": 0}}
      """
    Then the response status code should be 200
    # 100 - 50 = 50 remaining

    # Second request: 5M prompt tokens = $50 through route2 (shares budget)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-api-level/v1.0/anything/route2" with body:
      """
      {"usage": {"prompt_tokens": 5000000, "completion_tokens": 0}}
      """
    Then the response status code should be 200
    # 50 - 50 = 0 remaining

    # Third request should be blocked (budget exhausted)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-api-level/v1.0/anything/route1" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 0}}
      """
    Then the response status code should be 429

    When I send a POST request to "http://localhost:8080/budget-ratelimit-api-level/v1.0/anything/route2" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 0}}
      """
    Then the response status code should be 429

  Scenario: Rate limit headers include budget quota name
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-headers-api
      spec:
        displayName: Budget RateLimit Headers API
        version: v1.0
        context: /budget-ratelimit-headers/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  promptBudget:
                    limits:
                      - limit: 100
                        duration: "1h"
                  completionBudget:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-headers/v1.0/get" to be ready

    When I send a POST request to "http://localhost:8080/budget-ratelimit-headers/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 100000}}
      """
    Then the response status code should be 200
    # Check X-RateLimit-* headers (legacy format)
    And the response header "X-RateLimit-Limit" should exist
    And the response header "X-RateLimit-Remaining" should exist
    And the response header "X-RateLimit-Reset" should exist
    # Check IETF RateLimit headers
    And the response header "RateLimit-Policy" should exist
    And the response header "RateLimit" should exist
    # Verify IETF headers contain budget quota names
    And the response header "RateLimit-Policy" should contain "prompt-budget"
    And the response header "RateLimit-Policy" should contain "completion-budget"

  Scenario: Skip action on extraction failure (cost=0)
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-skip-api
      spec:
        displayName: Budget RateLimit Skip API
        version: v1.0
        context: /budget-ratelimit-skip/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  totalBudget:
                    limits:
                      - limit: 50
                        duration: "1h"
                  onExtractionFailure:
                    action: "skip"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-skip/v1.0/get" to be ready

    # First request with valid token counts: $40 cost
    When I send a POST request to "http://localhost:8080/budget-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 1000000}}
      """
    Then the response status code should be 200
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 1000000 × 0.00003 = $30
    # Total: $40
    # 50 - 40 = 10 remaining
    And the response header "X-RateLimit-Remaining" should be "10"

    # Second request with missing fields - should be skipped (cost=0)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-skip/v1.0/anything" with body:
      """
      {"other_data": "no tokens"}
      """
    Then the response status code should be 200
    # Still 10 remaining since this request was skipped

    # Third request with valid tokens: $10 cost
    When I send a POST request to "http://localhost:8080/budget-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 0}}
      """
    Then the response status code should be 200
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 0
    # 10 - 10 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Fourth request should be rate limited
    When I send a POST request to "http://localhost:8080/budget-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000, "completion_tokens": 1000}}
      """
    Then the response status code should be 429

  Scenario: Budget rate limiting using new tokenSource syntax with response_body
    # This test verifies that the new tokenSource configuration syntax works
    # with response_body type for budget-ratelimit policy
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-tokensource-api
      spec:
        displayName: Budget RateLimit TokenSource API
        version: v1.0
        context: /budget-ratelimit-tokensource/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  totalBudget:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-tokensource/v1.0/get" to be ready

    # Cost calculation:
    # - Prompt: 500,000 tokens × ($10/1M) = $5
    # - Completion: 500,000 tokens × ($30/1M) = $15
    # - Total cost per request: $20
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 500000, "completion_tokens": 500000}}
      """
    Then the response status code should be 200
    # 100 - 20 = 80 remaining
    And the response header "X-RateLimit-Remaining" should be "80"

    # Second request: same cost ($20)
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 500000, "completion_tokens": 500000}}
      """
    Then the response status code should be 200
    # 80 - 20 = 60 remaining
    And the response header "X-RateLimit-Remaining" should be "60"

    # Third request: $60 cost (exhausts budget)
    # Prompt: 1000000 × 0.00001 = $10
    # Completion: 1666667 × 0.00003 ≈ $50
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000000, "completion_tokens": 1666667}}
      """
    Then the response status code should be 200
    # 60 - 60 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Fourth request should be rate limited
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 1000, "completion_tokens": 1000}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Separate prompt and completion budgets with tokenSource syntax
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: budget-ratelimit-tokensource-separate-api
      spec:
        displayName: Budget RateLimit TokenSource Separate API
        version: v1.0
        context: /budget-ratelimit-tokensource-separate/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: budget-ratelimit
                version: v0.1.0
                params:
                  pricing:
                    promptTokens:
                      costPer1MTokens: 10.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.prompt_tokens"
                    completionTokens:
                      costPer1MTokens: 30.00
                      tokenSource:
                        type: response_body
                        jsonPath: "$.json.usage.completion_tokens"
                  promptBudget:
                    limits:
                      - limit: 50
                        duration: "1h"
                  completionBudget:
                    limits:
                      - limit: 30
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/budget-ratelimit-tokensource-separate/v1.0/get" to be ready

    # Test completion budget exhaustion (more restrictive in terms of cost)
    # Prompt budget: $50 limit, Completion budget: $30 limit
    # With 1M completion tokens at $30/1M = $30 cost
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 100000, "completion_tokens": 1000000}}
      """
    Then the response status code should be 200
    # Prompt cost: 100000 × 0.00001 = $1 (50 - 1 = 49 remaining)
    # Completion cost: 1000000 × 0.00003 = $30 (30 - 30 = 0 remaining, exhausted!)

    # Next request should be blocked by completion budget
    When I send a POST request to "http://localhost:8080/budget-ratelimit-tokensource-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 10000, "completion_tokens": 10000}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
