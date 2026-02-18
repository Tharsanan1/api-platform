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

package logger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestNewLogger_DefaultConfig(t *testing.T) {
	cfg := Config{
		Level:  "info",
		Format: "json",
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLogger_ConsoleFormat(t *testing.T) {
	cfg := Config{
		Level:  "debug",
		Format: "console",
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLogger_AllLogLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			cfg := Config{
				Level:  level,
				Format: "json",
			}

			logger, err := NewLogger(cfg)
			require.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestNewLoggerFromEnv(t *testing.T) {
	// Clear any existing LOG_LEVEL env var
	originalLevel := os.Getenv("LOG_LEVEL")
	os.Setenv("LOG_LEVEL", "debug")
	defer os.Setenv("LOG_LEVEL", originalLevel)

	logger, err := NewLoggerFromEnv()
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLoggerFromEnv_NoEnvVar(t *testing.T) {
	// Clear any existing LOG_LEVEL env var
	originalLevel := os.Getenv("LOG_LEVEL")
	os.Unsetenv("LOG_LEVEL")
	defer func() {
		if originalLevel != "" {
			os.Setenv("LOG_LEVEL", originalLevel)
		}
	}()

	logger, err := NewLoggerFromEnv()
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewDevelopmentLogger(t *testing.T) {
	logger, err := NewDevelopmentLogger()
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected zapcore.Level
	}{
		{"debug", zapcore.DebugLevel},
		{"DEBUG", zapcore.DebugLevel},
		{"Debug", zapcore.DebugLevel},
		{"info", zapcore.InfoLevel},
		{"INFO", zapcore.InfoLevel},
		{"Info", zapcore.InfoLevel},
		{"warn", zapcore.WarnLevel},
		{"WARN", zapcore.WarnLevel},
		{"warning", zapcore.WarnLevel},
		{"WARNING", zapcore.WarnLevel},
		{"error", zapcore.ErrorLevel},
		{"ERROR", zapcore.ErrorLevel},
		{"Error", zapcore.ErrorLevel},
		// Unknown levels default to Info
		{"", zapcore.InfoLevel},
		{"unknown", zapcore.InfoLevel},
		{"trace", zapcore.InfoLevel},
		{"fatal", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseLogLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	tests := []struct {
		envValue string
		expected zapcore.Level
	}{
		{"debug", zapcore.DebugLevel},
		{"info", zapcore.InfoLevel},
		{"warn", zapcore.WarnLevel},
		{"error", zapcore.ErrorLevel},
		{"", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.envValue, func(t *testing.T) {
			originalLevel := os.Getenv("LOG_LEVEL")
			if tt.envValue != "" {
				os.Setenv("LOG_LEVEL", tt.envValue)
			} else {
				os.Unsetenv("LOG_LEVEL")
			}
			defer func() {
				if originalLevel != "" {
					os.Setenv("LOG_LEVEL", originalLevel)
				} else {
					os.Unsetenv("LOG_LEVEL")
				}
			}()

			result := getLogLevel()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Level:  "debug",
		Format: "console",
	}

	assert.Equal(t, "debug", cfg.Level)
	assert.Equal(t, "console", cfg.Format)
}

func TestConfig_DefaultValues(t *testing.T) {
	cfg := Config{}

	assert.Empty(t, cfg.Level)
	assert.Empty(t, cfg.Format)
}

func TestNewLogger_CanLog(t *testing.T) {
	cfg := Config{
		Level:  "debug",
		Format: "json",
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	// These shouldn't panic
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	// Don't log error as it might affect test output
}

func TestNewDevelopmentLogger_CanLog(t *testing.T) {
	logger, err := NewDevelopmentLogger()
	require.NoError(t, err)

	// These shouldn't panic
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
}
