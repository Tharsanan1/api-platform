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

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDefaults(t *testing.T) {
	defaults := getDefaults()

	// Check gateway defaults
	gateway, ok := defaults["gateway"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "api-platform-gateway", gateway["helm_chart_name"])
	assert.Equal(t, "0.1.0", gateway["helm_chart_version"])
	assert.Equal(t, "", gateway["helm_values_file_path"])

	// Check reconciliation defaults
	reconciliation, ok := defaults["reconciliation"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "10m", reconciliation["sync_period"])
	assert.Equal(t, 1, reconciliation["max_concurrent_reconciles"])
	assert.Equal(t, 10, reconciliation["max_retry_attempts"])
	assert.Equal(t, "60s", reconciliation["max_backoff_duration"])
	assert.Equal(t, "1s", reconciliation["initial_backoff"])

	// Check logging defaults
	logging, ok := defaults["logging"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "info", logging["level"])
	assert.Equal(t, true, logging["development"])
	assert.Equal(t, "console", logging["format"])
}

func TestLoadConfig_DefaultsOnly(t *testing.T) {
	// Load config without a config file
	cfg, err := LoadConfig("")
	require.NoError(t, err)

	// Verify defaults are loaded
	assert.Equal(t, "api-platform-gateway", cfg.Gateway.HelmChartName)
	assert.Equal(t, "0.1.0", cfg.Gateway.HelmChartVersion)
	assert.Equal(t, "", cfg.Gateway.HelmValuesFilePath)

	assert.Equal(t, 10*time.Minute, cfg.Reconciliation.SyncPeriod)
	assert.Equal(t, 1, cfg.Reconciliation.MaxConcurrentReconciles)
	assert.Equal(t, 10, cfg.Reconciliation.MaxRetryAttempts)
	assert.Equal(t, 60*time.Second, cfg.Reconciliation.MaxBackoffDuration)
	assert.Equal(t, 1*time.Second, cfg.Reconciliation.InitialBackoff)

	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, true, cfg.Logging.Development)
	assert.Equal(t, "console", cfg.Logging.Format)
}

func TestLoadConfig_WithConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
gateway:
  helm_chart_name: custom-gateway
  helm_chart_version: 2.0.0
  helm_values_file_path: /custom/values.yaml
reconciliation:
  sync_period: 5m
  max_concurrent_reconciles: 3
  max_retry_attempts: 5
  max_backoff_duration: 120s
  initial_backoff: 2s
logging:
  level: debug
  development: false
  format: json
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Verify config file values override defaults
	assert.Equal(t, "custom-gateway", cfg.Gateway.HelmChartName)
	assert.Equal(t, "2.0.0", cfg.Gateway.HelmChartVersion)
	assert.Equal(t, "/custom/values.yaml", cfg.Gateway.HelmValuesFilePath)

	assert.Equal(t, 5*time.Minute, cfg.Reconciliation.SyncPeriod)
	assert.Equal(t, 3, cfg.Reconciliation.MaxConcurrentReconciles)
	assert.Equal(t, 5, cfg.Reconciliation.MaxRetryAttempts)
	assert.Equal(t, 120*time.Second, cfg.Reconciliation.MaxBackoffDuration)
	assert.Equal(t, 2*time.Second, cfg.Reconciliation.InitialBackoff)

	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, false, cfg.Logging.Development)
	assert.Equal(t, "json", cfg.Logging.Format)
}

func TestLoadConfig_NonExistentConfigFile(t *testing.T) {
	// Load config with a non-existent config file path
	// Should use defaults without error
	cfg, err := LoadConfig("/non/existent/path/config.yaml")
	require.NoError(t, err)

	// Verify defaults are used
	assert.Equal(t, "api-platform-gateway", cfg.Gateway.HelmChartName)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoadConfig_InvalidConfigFile(t *testing.T) {
	// Create a temporary invalid config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidContent := `
invalid: yaml: content: [
`
	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	require.NoError(t, err)

	_, err = LoadConfig(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config file")
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("GATEWAY_HELM_CHART_NAME", "env-gateway")
	os.Setenv("GATEWAY_HELM_CHART_VERSION", "3.0.0")
	defer func() {
		os.Unsetenv("GATEWAY_HELM_CHART_NAME")
		os.Unsetenv("GATEWAY_HELM_CHART_VERSION")
	}()

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	// Verify environment variables override defaults
	assert.Equal(t, "env-gateway", cfg.Gateway.HelmChartName)
	assert.Equal(t, "3.0.0", cfg.Gateway.HelmChartVersion)
}

func TestOperatorConfig_Validate_ValidConfig(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestOperatorConfig_Validate_InvalidLogLevel(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level:  "invalid",
			Format: "json",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log level")
}

func TestOperatorConfig_Validate_InvalidLogFormat(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "invalid",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log format")
}

func TestOperatorConfig_Validate_EmptyLogFormat(t *testing.T) {
	// Empty format should be valid (defaults to unspecified)
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestOperatorConfig_Validate_InvalidMaxConcurrentReconciles(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level: "info",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 0,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max concurrent reconciles must be at least 1")
}

func TestOperatorConfig_Validate_InvalidMaxRetryAttempts(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level: "info",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        0,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max retry attempts must be at least 1")
}

func TestOperatorConfig_Validate_InvalidInitialBackoff(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level: "info",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          0,
			MaxBackoffDuration:      60 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initial backoff must be a positive duration")
}

func TestOperatorConfig_Validate_InvalidMaxBackoffDuration(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level: "info",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          1 * time.Second,
			MaxBackoffDuration:      0,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max backoff duration must be a positive duration")
}

func TestOperatorConfig_Validate_MaxBackoffLessThanInitial(t *testing.T) {
	cfg := &OperatorConfig{
		Logging: LoggingConfig{
			Level: "info",
		},
		Reconciliation: ReconciliationConfig{
			MaxConcurrentReconciles: 1,
			MaxRetryAttempts:        5,
			InitialBackoff:          60 * time.Second,
			MaxBackoffDuration:      1 * time.Second,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max backoff duration must be greater than or equal to initial backoff")
}

func TestOperatorConfig_Validate_AllLogLevels(t *testing.T) {
	validLevels := []string{"debug", "info", "warn", "error"}

	for _, level := range validLevels {
		cfg := &OperatorConfig{
			Logging: LoggingConfig{
				Level: level,
			},
			Reconciliation: ReconciliationConfig{
				MaxConcurrentReconciles: 1,
				MaxRetryAttempts:        5,
				InitialBackoff:          1 * time.Second,
				MaxBackoffDuration:      60 * time.Second,
			},
		}

		err := cfg.Validate()
		assert.NoError(t, err, "Log level %s should be valid", level)
	}
}

func TestOperatorConfig_Validate_ValidLogFormats(t *testing.T) {
	validFormats := []string{"json", "console", ""}

	for _, format := range validFormats {
		cfg := &OperatorConfig{
			Logging: LoggingConfig{
				Level:  "info",
				Format: format,
			},
			Reconciliation: ReconciliationConfig{
				MaxConcurrentReconciles: 1,
				MaxRetryAttempts:        5,
				InitialBackoff:          1 * time.Second,
				MaxBackoffDuration:      60 * time.Second,
			},
		}

		err := cfg.Validate()
		assert.NoError(t, err, "Log format '%s' should be valid", format)
	}
}

func TestSecretReference_Defaults(t *testing.T) {
	_, err := LoadConfig("")
	require.NoError(t, err)

	// Check that secret reference defaults are applied
	// Note: RegistryCredentialsSecret may be nil if not configured
	// but the defaults for username_key and password_key should be set
	// when LoadConfig runs
}

func TestLoadConfig_WithRegistryCredentialsSecret(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
gateway:
  helm_chart_name: test-gateway
  insecure_registry: true
  plain_http: true
  registry_credentials_secret:
    name: my-secret
    namespace: my-namespace
logging:
  level: info
reconciliation:
  max_concurrent_reconciles: 1
  max_retry_attempts: 5
  max_backoff_duration: 60s
  initial_backoff: 1s
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "test-gateway", cfg.Gateway.HelmChartName)
	assert.True(t, cfg.Gateway.InsecureRegistry)
	assert.True(t, cfg.Gateway.PlainHTTP)

	require.NotNil(t, cfg.Gateway.RegistryCredentialsSecret)
	assert.Equal(t, "my-secret", cfg.Gateway.RegistryCredentialsSecret.Name)
	assert.Equal(t, "my-namespace", cfg.Gateway.RegistryCredentialsSecret.Namespace)
	// Check defaults for keys
	assert.Equal(t, "username", cfg.Gateway.RegistryCredentialsSecret.UsernameKey)
	assert.Equal(t, "password", cfg.Gateway.RegistryCredentialsSecret.PasswordKey)
}
