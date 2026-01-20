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

package budgetratelimit

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

// BudgetRateLimitPolicy provides budget-based rate limiting that delegates
// to the core ratelimit policy. It converts token counts to costs using
// configurable pricing (cost per 1M tokens) and enforces budget limits.
type BudgetRateLimitPolicy struct {
	delegate policy.Policy
}

// GetPolicy creates and initializes the budget rate limit policy.
// It transforms the budget-based configuration to a full ratelimit quota config
// and delegates to the core ratelimit policy.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Validate pricing configuration
	pricing, ok := params["pricing"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("pricing configuration is required")
	}

	promptPricing, ok := pricing["promptTokens"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("pricing.promptTokens configuration is required")
	}

	completionPricing, ok := pricing["completionTokens"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("pricing.completionTokens configuration is required")
	}

	// Validate required fields in pricing
	if _, ok := promptPricing["costPer1MTokens"]; !ok {
		return nil, fmt.Errorf("pricing.promptTokens.costPer1MTokens is required")
	}
	if _, ok := completionPricing["costPer1MTokens"]; !ok {
		return nil, fmt.Errorf("pricing.completionTokens.costPer1MTokens is required")
	}

	// Validate token source configuration for prompt tokens
	promptSource := getTokenSourceFromPricing(promptPricing)
	if promptSource == nil {
		return nil, fmt.Errorf("pricing.promptTokens requires either tokenSource or jsonPath to be configured")
	}

	// Validate token source configuration for completion tokens
	completionSource := getTokenSourceFromPricing(completionPricing)
	if completionSource == nil {
		return nil, fmt.Errorf("pricing.completionTokens requires either tokenSource or jsonPath to be configured")
	}

	// Validate that at least one budget is configured
	hasPromptBudget := hasBudgetConfig(params, "promptBudget")
	hasCompletionBudget := hasBudgetConfig(params, "completionBudget")
	hasTotalBudget := hasBudgetConfig(params, "totalBudget")

	if !hasPromptBudget && !hasCompletionBudget && !hasTotalBudget {
		return nil, fmt.Errorf("at least one of promptBudget, completionBudget, or totalBudget must be configured with limits")
	}

	// Transform to ratelimit params
	rlParams := transformToRatelimitParams(params, metadata)

	// Create the delegate ratelimit policy
	delegate, err := ratelimit.GetPolicy(metadata, rlParams)
	if err != nil {
		return nil, err
	}

	return &BudgetRateLimitPolicy{delegate: delegate}, nil
}

// hasBudgetConfig checks if a budget type has a valid configuration with limits
func hasBudgetConfig(params map[string]interface{}, budgetType string) bool {
	budgetConfig, ok := params[budgetType].(map[string]interface{})
	if !ok {
		return false
	}
	limits, ok := budgetConfig["limits"].([]interface{})
	return ok && len(limits) > 0
}

// getTokenSourceFromPricing extracts the token source configuration from a pricing config.
// It supports the new tokenSource object as well as the legacy jsonPath field.
// Returns nil if no valid source configuration is found.
func getTokenSourceFromPricing(pricingConfig map[string]interface{}) *tokenSourceConfig {
	// Check for new tokenSource configuration first
	if tokenSourceMap, ok := pricingConfig["tokenSource"].(map[string]interface{}); ok {
		sourceType, _ := tokenSourceMap["type"].(string)
		if sourceType == "" {
			sourceType = "response_body" // default
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

	// Fall back to legacy jsonPath field
	jsonPath, ok := pricingConfig["jsonPath"].(string)
	if !ok || jsonPath == "" {
		return nil
	}

	return &tokenSourceConfig{
		sourceType: "response_body",
		jsonPath:   jsonPath,
	}
}

// getDefaultCost returns the default cost based on onExtractionFailure configuration
// and applies the pricing multiplier
func getDefaultCost(params map[string]interface{}, multiplier float64) float64 {
	onFailure, ok := params["onExtractionFailure"].(map[string]interface{})
	if !ok {
		return 0 // skip action = 0 cost
	}

	action, _ := onFailure["action"].(string)
	if action == "default" {
		var defaultTokens float64
		if defaultVal, ok := onFailure["defaultValue"].(float64); ok {
			defaultTokens = defaultVal
		} else if defaultVal, ok := onFailure["defaultValue"].(int); ok {
			defaultTokens = float64(defaultVal)
		}
		return defaultTokens * multiplier
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

// transformToRatelimitParams converts the budget-based configuration to a full ratelimit
// quota configuration with cost extraction from response body, headers, or metadata using multipliers.
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

	// Extract pricing configuration
	pricing := params["pricing"].(map[string]interface{})
	promptPricing := pricing["promptTokens"].(map[string]interface{})
	completionPricing := pricing["completionTokens"].(map[string]interface{})

	// Calculate multipliers (cost per token = costPer1MTokens / 1,000,000)
	promptCostPer1M := getFloat64(promptPricing, "costPer1MTokens")
	completionCostPer1M := getFloat64(completionPricing, "costPer1MTokens")
	promptMultiplier := promptCostPer1M / 1_000_000
	completionMultiplier := completionCostPer1M / 1_000_000

	// Get token sources
	promptSource := getTokenSourceFromPricing(promptPricing)
	completionSource := getTokenSourceFromPricing(completionPricing)

	// Build quota for promptBudget if configured
	if hasBudgetConfig(params, "promptBudget") {
		promptBudget := params["promptBudget"].(map[string]interface{})
		defaultCost := getDefaultCost(params, promptMultiplier)

		quota := map[string]interface{}{
			"name":          "prompt-budget",
			"limits":        promptBudget["limits"],
			"keyExtraction": keyExtraction,
			"costExtraction": map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					buildCostExtractionSource(promptSource, promptMultiplier),
				},
				"default": defaultCost,
			},
		}
		quotas = append(quotas, quota)
	}

	// Build quota for completionBudget if configured
	if hasBudgetConfig(params, "completionBudget") {
		completionBudget := params["completionBudget"].(map[string]interface{})
		defaultCost := getDefaultCost(params, completionMultiplier)

		quota := map[string]interface{}{
			"name":          "completion-budget",
			"limits":        completionBudget["limits"],
			"keyExtraction": keyExtraction,
			"costExtraction": map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					buildCostExtractionSource(completionSource, completionMultiplier),
				},
				"default": defaultCost,
			},
		}
		quotas = append(quotas, quota)
	}

	// Build quota for totalBudget if configured
	// Uses both sources with their respective multipliers - advanced-ratelimit sums them
	if hasBudgetConfig(params, "totalBudget") {
		totalBudget := params["totalBudget"].(map[string]interface{})
		// For total budget default, use combined multiplier (prompt + completion)
		defaultCost := getDefaultCost(params, promptMultiplier+completionMultiplier)

		quota := map[string]interface{}{
			"name":          "total-budget",
			"limits":        totalBudget["limits"],
			"keyExtraction": keyExtraction,
			"costExtraction": map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{
					buildCostExtractionSource(promptSource, promptMultiplier),
					buildCostExtractionSource(completionSource, completionMultiplier),
				},
				"default": defaultCost,
			},
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

// getFloat64 safely extracts a float64 from a map, handling both float64 and int types
func getFloat64(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	if val, ok := m[key].(int); ok {
		return float64(val)
	}
	return 0
}

// Mode returns the processing mode for this policy.
// Since budget-ratelimit extracts costs from response body, it needs response body buffering.
func (p *BudgetRateLimitPolicy) Mode() policy.ProcessingMode {
	// Delegate to the underlying policy which will determine the correct mode
	// based on its cost extraction configuration
	return p.delegate.Mode()
}

// OnRequest delegates to the core ratelimit policy's OnRequest method.
func (p *BudgetRateLimitPolicy) OnRequest(
	ctx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	return p.delegate.OnRequest(ctx, params)
}

// OnResponse delegates to the core ratelimit policy's OnResponse method.
func (p *BudgetRateLimitPolicy) OnResponse(
	ctx *policy.ResponseContext,
	params map[string]interface{},
) policy.ResponseAction {
	return p.delegate.OnResponse(ctx, params)
}
