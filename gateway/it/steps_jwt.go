/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package it

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2/api-platform/gateway/it/steps"
)

// RegisterJWTSteps registers all JWT authentication step definitions
func RegisterJWTSteps(ctx *godog.ScenarioContext, state *TestState, httpSteps *steps.HTTPSteps) {
	ctx.Step(`^the mock JWKS server is ready$`, func() error {
		// Wait for mock JWKS server to be ready
		maxRetries := 10
		for i := 0; i < maxRetries; i++ {
			resp, err := state.HTTPClient.Get("http://localhost:9082/jwks")
			if err == nil && resp.StatusCode == 200 {
				resp.Body.Close()
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(1 * time.Second)
		}
		return fmt.Errorf("mock JWKS server not ready after %d retries", maxRetries)
	})

	ctx.Step(`^I request a JWT token from the mock server$`, func() error {
		resp, err := state.HTTPClient.Get("http://localhost:9082/token")
		if err != nil {
			return fmt.Errorf("failed to request JWT token: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("failed to get JWT token, status code: %d", resp.StatusCode)
		}

		token, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read JWT token: %w", err)
		}

		state.JWTToken = string(token)
		return nil
	})

	ctx.Step(`^I send a GET request to "([^"]*)" with JWT token$`, func(url string) error {
		if state.JWTToken == "" {
			return fmt.Errorf("no JWT token available")
		}

		httpSteps.SetHeader("Authorization", "Bearer "+state.JWTToken)
		return httpSteps.SendGET(url)
	})

	ctx.Step(`^I wait for the endpoint "([^"]*)" to be ready with JWT auth$`, func(url string) error {
		// Wait for endpoint to be ready (checking without auth to verify policy is in place)
		maxRetries := 20
		for i := 0; i < maxRetries; i++ {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			resp, err := state.HTTPClient.Do(req)
			if err == nil {
				resp.Body.Close()
				// If we get 401 Unauthorized, the endpoint is ready with auth
				if resp.StatusCode == 401 {
					return nil
				}
				// If we get 200, endpoint exists but auth might not be applied yet
				if resp.StatusCode == 200 {
					time.Sleep(500 * time.Millisecond)
					continue
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("endpoint not ready after %d retries", maxRetries)
	})

	ctx.Step(`^I send a GET request to "([^"]*)" with header "([^"]*)" value "([^"]*)"$`, func(url, headerName, headerValue string) error {
		// Replace {token} placeholder if present
		if strings.Contains(headerValue, "{token}") && state.JWTToken != "" {
			headerValue = strings.ReplaceAll(headerValue, "{token}", state.JWTToken)
		}
		httpSteps.SetHeader(headerName, headerValue)
		return httpSteps.SendGET(url)
	})
}
