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

// tokenSourceConfig represents the token extraction configuration
type tokenSourceConfig struct {
	sourceType string // "response_body", "response_header", "response_metadata"
	key        string // header name or metadata key
	jsonPath   string // JSON path for response_body
}

// TokenRateLimitPolicy provides token-based rate limiting that delegates
// to the core ratelimit policy. It supports separate limits for prompt tokens,
// completion tokens, and total tokens extracted from response body, headers, or metadata.
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
		totalSource := getTokenSource(params, "totalTokens")

		// If totalTokens has no direct token source, we need both prompt and completion sources for computation
		if totalSource == nil {
			promptSource := getTokenSource(params, "promptTokens")
			completionSource := getTokenSource(params, "completionTokens")
			if promptSource == nil || completionSource == nil {
				return nil, fmt.Errorf("totalTokens without tokenSource requires both promptTokens and completionTokens to have tokenSource configured for computed total")
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

// getTokenSource extracts the token source configuration from a token type.
// Returns nil if no valid source configuration is found.
func getTokenSource(params map[string]interface{}, tokenType string) *tokenSourceConfig {
	tokenConfig, ok := params[tokenType].(map[string]interface{})
	if !ok {
		return nil
	}

	// Get tokenSource configuration
	tokenSourceMap, ok := tokenConfig["tokenSource"].(map[string]interface{})
	if !ok {
		return nil
	}

	sourceType, _ := tokenSourceMap["type"].(string)
	if sourceType == "" {
		return nil // type is required
	}

	config := &tokenSourceConfig{
		sourceType: sourceType,
	}

	switch sourceType {
	case "response_header", "response_metadata":
		key, _ := tokenSourceMap["key"].(string)
		if key == "" {
			return nil // key is required for header/metadata
		}
		config.key = key
	case "response_body":
		jsonPath, _ := tokenSourceMap["jsonPath"].(string)
		if jsonPath == "" {
			return nil // jsonPath is required for body
		}
		config.jsonPath = jsonPath
	default:
		return nil // unsupported type
	}

	return config
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

// buildCostExtractionSource creates a cost extraction source map from a tokenSourceConfig
func buildCostExtractionSource(source *tokenSourceConfig, multiplier float64) map[string]interface{} {
	result := map[string]interface{}{
		"type":       source.sourceType,
		"multiplier": multiplier,
	}

	switch source.sourceType {
	case "response_header", "response_metadata":
		result["key"] = source.key
	case "response_body":
		result["jsonPath"] = source.jsonPath
	}

	return result
}

// transformToRatelimitParams converts the token-based configuration to a full ratelimit
// quota configuration with cost extraction from response body, headers, or metadata.
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
		promptSource := getTokenSource(params, "promptTokens")

		if promptSource != nil {
			quota := map[string]interface{}{
				"name":          "prompt-tokens",
				"limits":        promptTokens["limits"],
				"keyExtraction": keyExtraction,
				"costExtraction": map[string]interface{}{
					"enabled": true,
					"sources": []interface{}{
						buildCostExtractionSource(promptSource, 1.0),
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
		completionSource := getTokenSource(params, "completionTokens")

		if completionSource != nil {
			quota := map[string]interface{}{
				"name":          "completion-tokens",
				"limits":        completionTokens["limits"],
				"keyExtraction": keyExtraction,
				"costExtraction": map[string]interface{}{
					"enabled": true,
					"sources": []interface{}{
						buildCostExtractionSource(completionSource, 1.0),
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
		totalSource := getTokenSource(params, "totalTokens")

		var costExtraction map[string]interface{}

		if totalSource != nil {
			// Direct extraction from configured source
			costExtraction = map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					buildCostExtractionSource(totalSource, 1.0),
				},
				"default": defaultCost,
			}
		} else {
			// Computed from prompt + completion (validation ensures both exist)
			promptSource := getTokenSource(params, "promptTokens")
			completionSource := getTokenSource(params, "completionTokens")

			costExtraction = map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					buildCostExtractionSource(promptSource, 1.0),
					buildCostExtractionSource(completionSource, 1.0),
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
