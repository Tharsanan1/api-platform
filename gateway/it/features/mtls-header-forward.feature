# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

# Runs against a gateway configured with
#   [router.downstream_tls.client_certificate_header]
#   forward_to_backend = true
# (see test-config.mtls-header-forward.toml): cd it && make test-mtls-header-forward

@mtls @mtls-header-forward
Feature: Forwarding a believed relayed certificate to the backend
  As a backend owner behind a gateway that sits behind a front proxy
  I want the relayed client certificate forwarded to me when the gateway believed it
  So that my service can see who called, and never receives a header the gateway ignored

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And the client authority pool is empty
    And the certificate fixture "ca-a" is pooled as "fwd-partner-a" with usage "client"
    And I upload the certificate fixture "edge-lb-ca" as "fwd-edge-lb" with usage "client" and role "relay"
    And the response status should be 201
    And I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1
      kind: RestApi
      metadata:
        name: fwd-api
      spec:
        displayName: Forward API
        version: v1.0
        context: /fwd/$version
        upstream:
          main:
            url: http://echo-backend:80
        policies:
          - name: mtls-auth
            version: v1
            params:
              accept:
                - ca: fwd-partner-a
        operations:
          - method: GET
            path: /anything
      """
    And the response should be successful
    And I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1
      kind: RestApi
      metadata:
        name: fwd-public-api
      spec:
        displayName: Forward Public API
        version: v1.0
        context: /fwd-public/$version
        upstream:
          main:
            url: http://echo-backend:80
        operations:
          - method: GET
            path: /anything
      """
    And the response should be successful
    And I wait for the endpoint "http://localhost:8080/fwd-public/v1.0/anything" to be ready
    And I wait for the endpoint "http://localhost:8080/fwd/v1.0/anything" to respond with status 401

  Scenario: A header the gateway believed is forwarded, on protected and public routes alike
    When I send a GET request to "https://localhost:8443/fwd/v1.0/anything" with client certificate "edge-lb" and header "X-WSO2-CLIENT-CERTIFICATE" carrying certificate "client-valid"
    Then the response status code should be 200
    And the response should contain echoed header "x-wso2-client-certificate" containing "BEGIN"
    When I send a GET request to "https://localhost:8443/fwd-public/v1.0/anything" with client certificate "edge-lb" and header "X-WSO2-CLIENT-CERTIFICATE" carrying certificate "client-valid"
    Then the response status code should be 200
    And the response should contain echoed header "x-wso2-client-certificate" containing "BEGIN"

  Scenario: A header from a connection that is not the relay is deleted even with forwarding on
    When I send a GET request to "https://localhost:8443/fwd-public/v1.0/anything" with client certificate "client-valid" and header "X-WSO2-CLIENT-CERTIFICATE" carrying certificate "client-wrong-ca"
    Then the response status code should be 200
    And the response should not contain echoed header "x-wso2-client-certificate"
    When I send a GET request to "https://localhost:8443/fwd-public/v1.0/anything" with no client certificate and header "X-WSO2-CLIENT-CERTIFICATE" carrying certificate "client-valid"
    Then the response status code should be 200
    And the response should not contain echoed header "x-wso2-client-certificate"
    When I send a GET request to "https://localhost:8443/fwd/v1.0/anything" with client certificate "client-valid" and header "X-WSO2-CLIENT-CERTIFICATE" carrying certificate "client-wrong-ca"
    Then the response status code should be 200
    And the response should not contain echoed header "x-wso2-client-certificate"
