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

Feature: JWT Authentication Policy
  As an API developer
  I want to secure my APIs with JWT authentication
  So that only authenticated users with valid tokens can access my resources

  Background:
    Given the gateway services are running
    And the mock JWKS server is ready

  Scenario: Successful JWT authentication with valid token
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-auth-test-api
      spec:
        displayName: JWT Auth Test API
        version: v1.0
        context: /jwt-auth/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      issuer: http://mock-jwks.default.svc.cluster.local:8080/token
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/jwt-auth/v1.0/protected" to be ready with JWT auth

    When I request a JWT token from the mock server
    And I send a GET request to "http://localhost:8080/jwt-auth/v1.0/protected" with JWT token
    Then the response status code should be 200

  Scenario: JWT authentication fails without token
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-no-token-api
      spec:
        displayName: JWT No Token API
        version: v1.0
        context: /jwt-no-token/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I send a GET request to "http://localhost:8080/jwt-no-token/v1.0/protected"
    Then the response status code should be 401
    And the response should be valid JSON
    And the JSON response field "error" should be "Unauthorized"

  Scenario: JWT authentication fails with invalid token format
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-invalid-format-api
      spec:
        displayName: JWT Invalid Format API
        version: v1.0
        context: /jwt-invalid-format/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I send a GET request to "http://localhost:8080/jwt-invalid-format/v1.0/protected" with header "Authorization" value "Bearer invalid.token"
    Then the response status code should be 401

  Scenario: JWT authentication with audience validation
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-audience-api
      spec:
        displayName: JWT Audience API
        version: v1.0
        context: /jwt-audience/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
                  audiences:
                    - test-audience
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I request a JWT token from the mock server
    And I send a GET request to "http://localhost:8080/jwt-audience/v1.0/protected" with JWT token
    Then the response status code should be 200

  Scenario: JWT authentication with claim mappings to headers
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-claim-mapping-api
      spec:
        displayName: JWT Claim Mapping API
        version: v1.0
        context: /jwt-claim-mapping/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /headers
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
                  claimMappings:
                    sub: X-User-ID
                    iss: X-Issuer
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I request a JWT token from the mock server
    And I send a GET request to "http://localhost:8080/jwt-claim-mapping/v1.0/headers" with JWT token
    Then the response status code should be 200
    And the response should be valid JSON
    And the response body should contain "X-User-ID"
    And the response body should contain "test-user"

  Scenario: JWT authentication with custom header prefix
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-custom-prefix-api
      spec:
        displayName: JWT Custom Prefix API
        version: v1.0
        context: /jwt-custom-prefix/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
                  authHeaderPrefix: JWT
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I request a JWT token from the mock server
    And I send a GET request to "http://localhost:8080/jwt-custom-prefix/v1.0/protected" with header "Authorization" value "JWT {token}"
    Then the response status code should be 200

  Scenario: JWT authentication with custom error message
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: jwt-custom-error-api
      spec:
        displayName: JWT Custom Error API
        version: v1.0
        context: /jwt-custom-error/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /protected
            policies:
              - name: jwt-auth
                version: v0.1.0
                params:
                  keyManagers:
                    - name: test-jwks
                      jwks:
                        remote:
                          uri: http://mock-jwks:8080/jwks
                  onFailureStatusCode: 403
                  errorMessage: "Access Denied: Invalid or missing token"
      """
    Then the response should be successful
    And I wait for 2 seconds

    When I send a GET request to "http://localhost:8080/jwt-custom-error/v1.0/protected"
    Then the response status code should be 403
    And the response body should contain "Access Denied: Invalid or missing token"
