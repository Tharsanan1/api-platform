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

package tokenratelimit

import (
	"fmt"

	ratelimit "github.com/policy-engine/policies/advanced-ratelimit"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// TokenRateLimitPolicy provides token-based rate limiting that delegates
// to the core ratelimit policy. It supports separate limits for prompt tokens,
// completion tokens, and total tokens extracted from response body.
type TokenRateLimitPolicy struct {
	delegate policy.Policy
}

// GetPolicy creates and initializes the token rate limit policy.
// It transforms the token-based configuration to a full ratelimit quota config
// and delegates to the core ratelimit policy.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Validate that at least one token type is configured
	hasPrompt := hasTokenConfig(params, "promptTokens")
	hasCompletion := hasTokenConfig(params, "completionTokens")
	hasTotal := hasTokenConfig(params, "totalTokens")

	if !hasPrompt && !hasCompletion && !hasTotal {
		return nil, fmt.Errorf("at least one of promptTokens, completionTokens, or totalTokens must be configured with limits")
	}

	// Validate totalTokens configuration
	if hasTotal {
		totalTokens := params["totalTokens"].(map[string]interface{})
		totalJsonPath, hasTotalPath := totalTokens["jsonPath"].(string)

		// If totalTokens has no jsonPath, we need both prompt and completion jsonPaths for computation
		if !hasTotalPath || totalJsonPath == "" {
			promptPath := getJsonPath(params, "promptTokens")
			completionPath := getJsonPath(params, "completionTokens")
			if promptPath == "" || completionPath == "" {
				return nil, fmt.Errorf("totalTokens without jsonPath requires both promptTokens.jsonPath and completionTokens.jsonPath to be configured for computed total")
			}
		}
	}

	// Transform to ratelimit params
	rlParams := transformToRatelimitParams(params, metadata)

	// Create the delegate ratelimit policy
	delegate, err := ratelimit.GetPolicy(metadata, rlParams)
	if err != nil {
		return nil, err
	}

	return &TokenRateLimitPolicy{delegate: delegate}, nil
}

// hasTokenConfig checks if a token type has a valid configuration with limits
func hasTokenConfig(params map[string]interface{}, tokenType string) bool {
	tokenConfig, ok := params[tokenType].(map[string]interface{})
	if !ok {
		return false
	}
	limits, ok := tokenConfig["limits"].([]interface{})
	return ok && len(limits) > 0
}

// getJsonPath extracts jsonPath from a token type configuration
func getJsonPath(params map[string]interface{}, tokenType string) string {
	tokenConfig, ok := params[tokenType].(map[string]interface{})
	if !ok {
		return ""
	}
	jsonPath, _ := tokenConfig["jsonPath"].(string)
	return jsonPath
}

// getDefaultValue returns the default cost based on onExtractionFailure configuration
func getDefaultValue(params map[string]interface{}) float64 {
	onFailure, ok := params["onExtractionFailure"].(map[string]interface{})
	if !ok {
		return 0 // skip action = 0 cost
	}

	action, _ := onFailure["action"].(string)
	if action == "default" {
		if defaultVal, ok := onFailure["defaultValue"].(float64); ok {
			return defaultVal
		}
		if defaultVal, ok := onFailure["defaultValue"].(int); ok {
			return float64(defaultVal)
		}
	}

	return 0 // skip action = 0 cost
}

// transformToRatelimitParams converts the token-based configuration to a full ratelimit
// quota configuration with cost extraction from response body.
func transformToRatelimitParams(params map[string]interface{}, metadata policy.PolicyMetadata) map[string]interface{} {
	quotas := []interface{}{}

	// Determine key extraction based on attachment level
	keyExtractorType := "routename"
	if metadata.AttachedTo == policy.LevelAPI {
		keyExtractorType = "apiname"
	}

	keyExtraction := []interface{}{
		map[string]interface{}{"type": keyExtractorType},
	}

	defaultCost := getDefaultValue(params)

	// Build quota for promptTokens if configured
	if hasTokenConfig(params, "promptTokens") {
		promptTokens := params["promptTokens"].(map[string]interface{})
		jsonPath := getJsonPath(params, "promptTokens")

		if jsonPath != "" {
			quota := map[string]interface{}{
				"name":          "prompt-tokens",
				"limits":        promptTokens["limits"],
				"keyExtraction": keyExtraction,
				"costExtraction": map[string]interface{}{
					"enabled": true,
					"sources": []interface{}{
						map[string]interface{}{
							"type":       "response_body",
							"jsonPath":   jsonPath,
							"multiplier": 1.0,
						},
					},
					"default": defaultCost,
				},
			}
			quotas = append(quotas, quota)
		}
	}

	// Build quota for completionTokens if configured
	if hasTokenConfig(params, "completionTokens") {
		completionTokens := params["completionTokens"].(map[string]interface{})
		jsonPath := getJsonPath(params, "completionTokens")

		if jsonPath != "" {
			quota := map[string]interface{}{
				"name":          "completion-tokens",
				"limits":        completionTokens["limits"],
				"keyExtraction": keyExtraction,
				"costExtraction": map[string]interface{}{
					"enabled": true,
					"sources": []interface{}{
						map[string]interface{}{
							"type":       "response_body",
							"jsonPath":   jsonPath,
							"multiplier": 1.0,
						},
					},
					"default": defaultCost,
				},
			}
			quotas = append(quotas, quota)
		}
	}

	// Build quota for totalTokens if configured
	if hasTokenConfig(params, "totalTokens") {
		totalTokens := params["totalTokens"].(map[string]interface{})
		totalJsonPath := getJsonPath(params, "totalTokens")

		var costExtraction map[string]interface{}

		if totalJsonPath != "" {
			// Direct extraction from response body
			costExtraction = map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					map[string]interface{}{
						"type":       "response_body",
						"jsonPath":   totalJsonPath,
						"multiplier": 1.0,
					},
				},
				"default": defaultCost,
			}
		} else {
			// Computed from prompt + completion (validation ensures both exist)
			promptPath := getJsonPath(params, "promptTokens")
			completionPath := getJsonPath(params, "completionTokens")

			costExtraction = map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					map[string]interface{}{
						"type":       "response_body",
						"jsonPath":   promptPath,
						"multiplier": 1.0,
					},
					map[string]interface{}{
						"type":       "response_body",
						"jsonPath":   completionPath,
						"multiplier": 1.0,
					},
				},
				"default": defaultCost,
			}
		}

		quota := map[string]interface{}{
			"name":           "total-tokens",
			"limits":         totalTokens["limits"],
			"keyExtraction":  keyExtraction,
			"costExtraction": costExtraction,
		}
		quotas = append(quotas, quota)
	}

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

// Mode returns the processing mode for this policy.
// Since token-ratelimit extracts costs from response body, it needs response body buffering.
func (p *TokenRateLimitPolicy) Mode() policy.ProcessingMode {
	// Delegate to the underlying policy which will determine the correct mode
	// based on its cost extraction configuration
	return p.delegate.Mode()
}

// OnRequest delegates to the core ratelimit policy's OnRequest method.
func (p *TokenRateLimitPolicy) OnRequest(
	ctx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	return p.delegate.OnRequest(ctx, params)
}

// OnResponse delegates to the core ratelimit policy's OnResponse method.
func (p *TokenRateLimitPolicy) OnResponse(
	ctx *policy.ResponseContext,
	params map[string]interface{},
) policy.ResponseAction {
	return p.delegate.OnResponse(ctx, params)
}
