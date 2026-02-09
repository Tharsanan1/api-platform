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

package discovery

import "log/slog"

const (
	// internalConfigRefKey and internalDefaultValueKey are internal marker keys used by
	// policy-engine config resolution. When both wso2/defaultValue and default exist for
	// a property, builder emits a marker map so runtime can fallback to schema default
	// only when config lookup fails due to missing keys.
	internalConfigRefKey    = "__wso2_internal_ref"
	internalDefaultValueKey = "__wso2_internal_default"
)

// ExtractDefaultValues extracts default values from a JSON schema structure.
// It processes the "properties" object and extracts either "default" or "wso2/defaultValue"
// with precedence given to "wso2/defaultValue" when both exist.
//
// Input schema format (from systemParameters in policy-definition.yaml):
//
//	{
//	  "type": "object",
//	  "properties": {
//	    "propName": {
//	      "type": "string",
//	      "default": "value1",
//	      "wso2/defaultValue": "${configPath.To.Config}"
//	    }
//	  }
//	}
//
// Returns: map[string]interface{} with extracted values.
//
// If both wso2/defaultValue and default are present for a property, a marker map is returned:
//
//	{
//	  "__wso2_internal_ref": "${config.Path.To.Config}",
//	  "__wso2_internal_default": "fallback-value"
//	}
//
// Nested object properties are traversed recursively.
func ExtractDefaultValues(schema map[string]interface{}) map[string]interface{} {
	// Handle nil or empty schema
	if schema == nil {
		slog.Debug("Schema is nil, returning empty map", "phase", "discovery")
		return map[string]interface{}{}
	}

	return extractDefaultsFromSchema(schema)
}

func extractDefaultsFromSchema(schema map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Extract properties object
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		slog.Debug("No properties found in schema", "phase", "discovery")
		return result
	}

	slog.Debug("Extracting defaults from schema",
		"propertyCount", len(properties),
		"phase", "discovery")

	// Iterate through each property
	for propName, propDef := range properties {
		propDefMap, ok := propDef.(map[string]interface{})
		if !ok {
			slog.Debug("Property definition is not a map, skipping",
				"property", propName,
				"phase", "discovery")
			continue
		}

		if extractedValue, hasValue := extractPropertyValue(propDefMap); hasValue {
			result[propName] = extractedValue
			slog.Debug("Extracted property value",
				"property", propName,
				"value", extractedValue,
				"phase", "discovery")
			continue
		}

		// No direct default values on this property, recurse if this is an object schema.
		nested := extractDefaultsFromSchema(propDefMap)
		if len(nested) > 0 {
			result[propName] = nested
			slog.Debug("Extracted nested defaults",
				"property", propName,
				"value", nested,
				"phase", "discovery")
		}
	}

	slog.Debug("Extraction complete",
		"extractedCount", len(result),
		"phase", "discovery")

	return result
}

func extractPropertyValue(propDefMap map[string]interface{}) (interface{}, bool) {
	wso2Default, hasWso2Default := propDefMap["wso2/defaultValue"]
	defaultValue, hasDefault := propDefMap["default"]

	switch {
	case hasWso2Default && hasDefault:
		return map[string]interface{}{
			internalConfigRefKey:    wso2Default,
			internalDefaultValueKey: defaultValue,
		}, true
	case hasWso2Default:
		return wso2Default, true
	case hasDefault:
		return defaultValue, true
	default:
		return nil, false
	}
}
