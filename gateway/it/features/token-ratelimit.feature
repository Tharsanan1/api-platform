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

@token-ratelimit
Feature: Token Rate Limiting
  As an API developer
  I want to limit the rate of requests based on token consumption
  So that I can control LLM API usage per token type

  Background:
    Given the gateway services are running

  Scenario: Basic total token rate limiting
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-total-api
      spec:
        displayName: Token RateLimit Total API
        version: v1.0
        context: /token-ratelimit-total/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  totalTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.total_tokens"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-total/v1.0/get" to be ready

    # Send a POST request with total_tokens=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 50}}
      """
    Then the response status code should be 200
    # After first request: 100 - 50 = 50 remaining
    And the response header "X-RateLimit-Remaining" should be "50"

    # Send another request with total_tokens=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 50}}
      """
    Then the response status code should be 200
    # After second request: 50 - 50 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Third request should be rate limited since quota is exhausted
    When I send a POST request to "http://localhost:8080/token-ratelimit-total/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Separate prompt and completion token limits
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-separate-api
      spec:
        displayName: Token RateLimit Separate API
        version: v1.0
        context: /token-ratelimit-separate/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  promptTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.prompt_tokens"
                  completionTokens:
                    limits:
                      - limit: 50
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.completion_tokens"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-separate/v1.0/get" to be ready

    # Test completion limit (more restrictive: 50 tokens)
    # Send request with low prompt tokens (20) but high completion tokens (25)
    When I send a POST request to "http://localhost:8080/token-ratelimit-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 20, "completion_tokens": 25}}
      """
    Then the response status code should be 200
    # prompt-tokens: 100 - 20 = 80 remaining
    # completion-tokens: 50 - 25 = 25 remaining

    # Send another request with same pattern
    When I send a POST request to "http://localhost:8080/token-ratelimit-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 20, "completion_tokens": 25}}
      """
    Then the response status code should be 200
    # prompt-tokens: 80 - 20 = 60 remaining
    # completion-tokens: 25 - 25 = 0 remaining (exhausted!)

    # This request should be blocked by completion-tokens quota
    When I send a POST request to "http://localhost:8080/token-ratelimit-separate/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 10, "completion_tokens": 10}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Computed total tokens from prompt + completion
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-computed-api
      spec:
        displayName: Token RateLimit Computed API
        version: v1.0
        context: /token-ratelimit-computed/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  promptTokens:
                    limits:
                      - limit: 1000
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.prompt_tokens"
                  completionTokens:
                    limits:
                      - limit: 1000
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.completion_tokens"
                  totalTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-computed/v1.0/get" to be ready

    # totalTokens has no jsonPath, so total = prompt + completion (computed)
    # Send request with prompt=30, completion=20 -> total=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 30, "completion_tokens": 20}}
      """
    Then the response status code should be 200
    # total-tokens: 100 - 50 = 50 remaining

    # Send another request with prompt=25, completion=25 -> total=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 25, "completion_tokens": 25}}
      """
    Then the response status code should be 200
    # total-tokens: 50 - 50 = 0 remaining

    # Third request should be blocked by total-tokens quota (computed)
    When I send a POST request to "http://localhost:8080/token-ratelimit-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 5, "completion_tokens": 5}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Default value on extraction failure
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-default-api
      spec:
        displayName: Token RateLimit Default API
        version: v1.0
        context: /token-ratelimit-default/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  totalTokens:
                    limits:
                      - limit: 50
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.nonexistent_field"
                  onExtractionFailure:
                    action: "default"
                    defaultValue: 25
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-default/v1.0/get" to be ready

    # Send a request with body that doesn't contain the expected field
    # Cost extraction will fail, so default value (25) should be used
    When I send a POST request to "http://localhost:8080/token-ratelimit-default/v1.0/anything" with body:
      """
      {"usage": {"other_field": 100}}
      """
    Then the response status code should be 200
    # After first request: 50 - 25 = 25 remaining (default value used)
    And the response header "X-RateLimit-Remaining" should be "25"

    # Send another request - again default value (25) should be used
    When I send a POST request to "http://localhost:8080/token-ratelimit-default/v1.0/anything" with body:
      """
      {"usage": {"another_field": 200}}
      """
    Then the response status code should be 200
    # After second request: 25 - 25 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Third request should be rate limited
    When I send a POST request to "http://localhost:8080/token-ratelimit-default/v1.0/anything" with body:
      """
      {"data": "test"}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Skip action on extraction failure (fail-open)
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-skip-api
      spec:
        displayName: Token RateLimit Skip API
        version: v1.0
        context: /token-ratelimit-skip/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  totalTokens:
                    limits:
                      - limit: 50
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.total_tokens"
                  onExtractionFailure:
                    action: "skip"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-skip/v1.0/get" to be ready

    # First request with valid token count
    When I send a POST request to "http://localhost:8080/token-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 40}}
      """
    Then the response status code should be 200
    # 50 - 40 = 10 remaining
    And the response header "X-RateLimit-Remaining" should be "10"

    # Second request with missing field - should be skipped (cost=0)
    When I send a POST request to "http://localhost:8080/token-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"other_field": 100}}
      """
    Then the response status code should be 200
    # Still 10 remaining since this request was skipped

    # Third request with tokens should continue from 10 remaining
    When I send a POST request to "http://localhost:8080/token-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 200
    # 10 - 10 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Fourth request should be rate limited
    When I send a POST request to "http://localhost:8080/token-ratelimit-skip/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 5}}
      """
    Then the response status code should be 429

  Scenario: Multiple limits per token type
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-multilimits-api
      spec:
        displayName: Token RateLimit Multi-Limits API
        version: v1.0
        context: /token-ratelimit-multilimits/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  totalTokens:
                    limits:
                      - limit: 100
                        duration: "1m"
                      - limit: 50
                        duration: "24h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.total_tokens"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-multilimits/v1.0/get" to be ready

    # The 24h limit (50) is more restrictive than the 1m limit (100)
    # Send request with 30 tokens
    When I send a POST request to "http://localhost:8080/token-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 30}}
      """
    Then the response status code should be 200
    # 1m limit: 100 - 30 = 70 remaining
    # 24h limit: 50 - 30 = 20 remaining

    # Send request with 20 tokens (exhausts 24h limit)
    When I send a POST request to "http://localhost:8080/token-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 20}}
      """
    Then the response status code should be 200
    # 1m limit: 70 - 20 = 50 remaining
    # 24h limit: 20 - 20 = 0 remaining (exhausted!)

    # Third request should be blocked by 24h limit (even though 1m limit has 50 remaining)
    When I send a POST request to "http://localhost:8080/token-ratelimit-multilimits/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: API-level token rate limiting
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-api-level-api
      spec:
        displayName: Token RateLimit API Level
        version: v1.0
        context: /token-ratelimit-api-level/$version
        upstream:
          main:
            url: http://echo-backend:80
        policies:
          - name: token-ratelimit
            version: v0.1.0
            params:
              totalTokens:
                limits:
                  - limit: 100
                    duration: "1h"
                tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.total_tokens"
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything/route1
          - method: POST
            path: /anything/route2
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-api-level/v1.0/get" to be ready

    # API-level policy uses apiname as key - all routes share the same budget
    # Send 60 tokens through route1
    When I send a POST request to "http://localhost:8080/token-ratelimit-api-level/v1.0/anything/route1" with body:
      """
      {"usage": {"total_tokens": 60}}
      """
    Then the response status code should be 200
    # 100 - 60 = 40 remaining (API-level)

    # Send 40 tokens through route2 - shares budget with route1
    When I send a POST request to "http://localhost:8080/token-ratelimit-api-level/v1.0/anything/route2" with body:
      """
      {"usage": {"total_tokens": 40}}
      """
    Then the response status code should be 200
    # 40 - 40 = 0 remaining (API-level exhausted)

    # Both routes should now be rate limited
    When I send a POST request to "http://localhost:8080/token-ratelimit-api-level/v1.0/anything/route1" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 429

    When I send a POST request to "http://localhost:8080/token-ratelimit-api-level/v1.0/anything/route2" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 429

  Scenario: Rate limit headers include quota name
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-headers-api
      spec:
        displayName: Token RateLimit Headers API
        version: v1.0
        context: /token-ratelimit-headers/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  promptTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.prompt_tokens"
                  completionTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.completion_tokens"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-headers/v1.0/get" to be ready

    When I send a POST request to "http://localhost:8080/token-ratelimit-headers/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 10, "completion_tokens": 10}}
      """
    Then the response status code should be 200
    # Check X-RateLimit-* headers (legacy format)
    And the response header "X-RateLimit-Limit" should exist
    And the response header "X-RateLimit-Remaining" should exist
    And the response header "X-RateLimit-Reset" should exist
    # Check IETF RateLimit headers
    And the response header "RateLimit-Policy" should exist
    And the response header "RateLimit" should exist
    # Verify IETF headers contain quota names
    And the response header "RateLimit-Policy" should contain "prompt-tokens"
    And the response header "RateLimit-Policy" should contain "completion-tokens"

  Scenario: Token extraction using new tokenSource syntax with response_body
    # This test verifies that the new tokenSource configuration syntax works
    # with response_body type, which is functionally equivalent to the legacy jsonPath
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-tokensource-api
      spec:
        displayName: Token RateLimit TokenSource API
        version: v1.0
        context: /token-ratelimit-tokensource/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  totalTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.total_tokens"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-tokensource/v1.0/get" to be ready

    # Send a POST request with total_tokens=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 50}}
      """
    Then the response status code should be 200
    # After first request: 100 - 50 = 50 remaining
    And the response header "X-RateLimit-Remaining" should be "50"

    # Send another request with total_tokens=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 50}}
      """
    Then the response status code should be 200
    # After second request: 50 - 50 = 0 remaining
    And the response header "X-RateLimit-Remaining" should be "0"

    # Third request should be rate limited since quota is exhausted
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource/v1.0/anything" with body:
      """
      {"usage": {"total_tokens": 10}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"

  Scenario: Computed total tokens with tokenSource syntax
    # Test that computed total tokens works with the new tokenSource syntax
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: token-ratelimit-tokensource-computed-api
      spec:
        displayName: Token RateLimit TokenSource Computed API
        version: v1.0
        context: /token-ratelimit-tokensource-computed/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /get
          - method: POST
            path: /anything
            policies:
              - name: token-ratelimit
                version: v0.1.0
                params:
                  promptTokens:
                    limits:
                      - limit: 1000
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.prompt_tokens"
                  completionTokens:
                    limits:
                      - limit: 1000
                        duration: "1h"
                    tokenSource:
                      type: response_body
                      jsonPath: "$.json.usage.completion_tokens"
                  totalTokens:
                    limits:
                      - limit: 100
                        duration: "1h"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/token-ratelimit-tokensource-computed/v1.0/get" to be ready

    # totalTokens has no tokenSource, so total = prompt + completion (computed)
    # Send request with prompt=30, completion=20 -> total=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 30, "completion_tokens": 20}}
      """
    Then the response status code should be 200
    # total-tokens: 100 - 50 = 50 remaining

    # Send another request with prompt=25, completion=25 -> total=50
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 25, "completion_tokens": 25}}
      """
    Then the response status code should be 200
    # total-tokens: 50 - 50 = 0 remaining

    # Third request should be blocked by total-tokens quota (computed)
    When I send a POST request to "http://localhost:8080/token-ratelimit-tokensource-computed/v1.0/anything" with body:
      """
      {"usage": {"prompt_tokens": 5, "completion_tokens": 5}}
      """
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
