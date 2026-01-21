/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetReleaseName(t *testing.T) {
	tests := []struct {
		gatewayName string
		expected    string
	}{
		{
			gatewayName: "my-gateway",
			expected:    "my-gateway-gateway",
		},
		{
			gatewayName: "production",
			expected:    "production-gateway",
		},
		{
			gatewayName: "api-gw-1",
			expected:    "api-gw-1-gateway",
		},
		{
			gatewayName: "a",
			expected:    "a-gateway",
		},
		{
			gatewayName: "test-gateway-123",
			expected:    "test-gateway-123-gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.gatewayName, func(t *testing.T) {
			result := GetReleaseName(tt.gatewayName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToStringMap_SimpleMap(t *testing.T) {
	input := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	result, err := convertToStringMap(input)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "value1", resultMap["key1"])
	assert.Equal(t, 123, resultMap["key2"])
	assert.Equal(t, true, resultMap["key3"])
}

func TestConvertToStringMap_NestedMap(t *testing.T) {
	input := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": "value",
		},
	}

	result, err := convertToStringMap(input)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	outer, ok := resultMap["outer"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value", outer["inner"])
}

func TestConvertToStringMap_MapWithInterfaceKeys(t *testing.T) {
	// yaml.v2 creates map[interface{}]interface{}, this simulates that
	input := map[interface{}]interface{}{
		"key1": "value1",
		"key2": map[interface{}]interface{}{
			"nested": "nested-value",
		},
	}

	result, err := convertToStringMap(input)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "value1", resultMap["key1"])

	nested, ok := resultMap["key2"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "nested-value", nested["nested"])
}

func TestConvertToStringMap_Slice(t *testing.T) {
	input := []interface{}{
		"item1",
		"item2",
		map[string]interface{}{
			"key": "value",
		},
	}

	result, err := convertToStringMap(input)
	require.NoError(t, err)

	resultSlice, ok := result.([]interface{})
	require.True(t, ok)

	assert.Len(t, resultSlice, 3)
	assert.Equal(t, "item1", resultSlice[0])
	assert.Equal(t, "item2", resultSlice[1])

	item3, ok := resultSlice[2].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value", item3["key"])
}

func TestConvertToStringMap_NonStringKey(t *testing.T) {
	input := map[interface{}]interface{}{
		123: "value", // non-string key
	}

	_, err := convertToStringMap(input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-string key found")
}

func TestConvertToStringMap_PrimitiveTypes(t *testing.T) {
	// Test string
	result, err := convertToStringMap("test")
	require.NoError(t, err)
	assert.Equal(t, "test", result)

	// Test int
	result, err = convertToStringMap(42)
	require.NoError(t, err)
	assert.Equal(t, 42, result)

	// Test bool
	result, err = convertToStringMap(true)
	require.NoError(t, err)
	assert.Equal(t, true, result)

	// Test float
	result, err = convertToStringMap(3.14)
	require.NoError(t, err)
	assert.Equal(t, 3.14, result)

	// Test nil
	result, err = convertToStringMap(nil)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestConvertToStringMap_ComplexStructure(t *testing.T) {
	input := map[interface{}]interface{}{
		"gateway": map[interface{}]interface{}{
			"image": "wso2/gateway:latest",
			"replicas": 3,
			"resources": map[interface{}]interface{}{
				"requests": map[interface{}]interface{}{
					"cpu":    "100m",
					"memory": "256Mi",
				},
			},
			"tolerations": []interface{}{
				map[interface{}]interface{}{
					"key":      "dedicated",
					"operator": "Equal",
					"value":    "api-gateway",
				},
			},
		},
	}

	result, err := convertToStringMap(input)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	gateway, ok := resultMap["gateway"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "wso2/gateway:latest", gateway["image"])
	assert.Equal(t, 3, gateway["replicas"])

	resources, ok := gateway["resources"].(map[string]interface{})
	require.True(t, ok)

	requests, ok := resources["requests"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "100m", requests["cpu"])
	assert.Equal(t, "256Mi", requests["memory"])

	tolerations, ok := gateway["tolerations"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tolerations, 1)

	toleration, ok := tolerations[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "dedicated", toleration["key"])
}

func TestExtractRegistryHost(t *testing.T) {
	tests := []struct {
		name      string
		chartRef  string
		expected  string
		expectErr bool
	}{
		{
			name:      "OCI with full path",
			chartRef:  "oci://registry-1.docker.io/tharsanan/api-platform-gateway",
			expected:  "registry-1.docker.io",
			expectErr: false,
		},
		{
			name:      "OCI without trailing path",
			chartRef:  "oci://ghcr.io/wso2/charts",
			expected:  "ghcr.io",
			expectErr: false,
		},
		{
			name:      "Without OCI prefix",
			chartRef:  "registry-1.docker.io/tharsanan/chart",
			expected:  "registry-1.docker.io",
			expectErr: false,
		},
		{
			name:      "Simple hostname",
			chartRef:  "my-registry.example.com",
			expected:  "my-registry.example.com",
			expectErr: false,
		},
		{
			name:      "Hostname with port",
			chartRef:  "localhost:5000/my-chart",
			expected:  "localhost:5000",
			expectErr: false,
		},
		{
			name:      "Just hostname no path",
			chartRef:  "oci://myregistry.io",
			expected:  "myregistry.io",
			expectErr: false,
		},
		{
			name:      "Empty string",
			chartRef:  "",
			expectErr: true,
		},
		{
			name:      "Only oci prefix",
			chartRef:  "oci://",
			expected:  "oci:",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractRegistryHost(tt.chartRef)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestInstallOrUpgradeOptions_Struct(t *testing.T) {
	// Test that struct can be constructed with all fields
	opts := InstallOrUpgradeOptions{
		ReleaseName:     "my-release",
		Namespace:       "default",
		ChartName:       "oci://registry/chart",
		RepoURL:         "https://charts.example.com",
		Version:         "1.0.0",
		ValuesYAML:      "key: value",
		ValuesFilePath:  "/path/to/values.yaml",
		CreateNamespace: true,
		Wait:            true,
		Timeout:         300,
		Username:        "user",
		Password:        "pass",
		Insecure:        true,
		PlainHTTP:       false,
	}

	assert.Equal(t, "my-release", opts.ReleaseName)
	assert.Equal(t, "default", opts.Namespace)
	assert.Equal(t, "oci://registry/chart", opts.ChartName)
	assert.Equal(t, "https://charts.example.com", opts.RepoURL)
	assert.Equal(t, "1.0.0", opts.Version)
	assert.Equal(t, "key: value", opts.ValuesYAML)
	assert.Equal(t, "/path/to/values.yaml", opts.ValuesFilePath)
	assert.True(t, opts.CreateNamespace)
	assert.True(t, opts.Wait)
	assert.Equal(t, int64(300), opts.Timeout)
	assert.Equal(t, "user", opts.Username)
	assert.Equal(t, "pass", opts.Password)
	assert.True(t, opts.Insecure)
	assert.False(t, opts.PlainHTTP)
}

func TestUninstallOptions_Struct(t *testing.T) {
	// Test that struct can be constructed with all fields
	opts := UninstallOptions{
		ReleaseName: "my-release",
		Namespace:   "default",
		Wait:        true,
		Timeout:     120,
	}

	assert.Equal(t, "my-release", opts.ReleaseName)
	assert.Equal(t, "default", opts.Namespace)
	assert.True(t, opts.Wait)
	assert.Equal(t, int64(120), opts.Timeout)
}
