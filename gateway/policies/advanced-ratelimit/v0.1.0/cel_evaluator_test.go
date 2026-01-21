package ratelimit

import (
	"sync"
	"testing"
)

func TestExtractJSONPathValue(t *testing.T) {
	tests := []struct {
		name      string
		jsonData  []byte
		jsonPath  string
		expected  interface{}
		expectErr bool
	}{
		{
			name:     "extract string value",
			jsonData: []byte(`{"name": "test", "value": 123}`),
			jsonPath: "$.name",
			expected: "test",
		},
		{
			name:     "extract numeric value",
			jsonData: []byte(`{"name": "test", "value": 123}`),
			jsonPath: "$.value",
			expected: float64(123),
		},
		{
			name:     "extract nested value",
			jsonData: []byte(`{"user": {"id": "user123", "score": 456}}`),
			jsonPath: "$.user.id",
			expected: "user123",
		},
		{
			name:     "extract deeply nested value",
			jsonData: []byte(`{"data": {"usage": {"total_tokens": 100}}}`),
			jsonPath: "$.data.usage.total_tokens",
			expected: float64(100),
		},
		{
			name:     "extract array element",
			jsonData: []byte(`{"items": ["a", "b", "c"]}`),
			jsonPath: "$.items[0]",
			expected: "a",
		},
		{
			name:     "extract negative array index",
			jsonData: []byte(`{"items": ["a", "b", "c"]}`),
			jsonPath: "$.items[-1]",
			expected: "c",
		},
		{
			name:      "missing path",
			jsonData:  []byte(`{"name": "test"}`),
			jsonPath:  "$.nonexistent",
			expectErr: true,
		},
		{
			name:      "invalid JSON",
			jsonData:  []byte(`{invalid json}`),
			jsonPath:  "$.name",
			expectErr: true,
		},
		{
			name:      "empty JSON",
			jsonData:  []byte{},
			jsonPath:  "$.name",
			expectErr: true,
		},
		{
			name:     "boolean value",
			jsonData: []byte(`{"enabled": true}`),
			jsonPath: "$.enabled",
			expected: true,
		},
		{
			name:     "float value",
			jsonData: []byte(`{"price": 19.99}`),
			jsonPath: "$.price",
			expected: float64(19.99),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractJSONPathValue(tt.jsonData, tt.jsonPath)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %v (%T), got %v (%T)", tt.expected, tt.expected, result, result)
			}
		})
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "string input",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "int input",
			input:    42,
			expected: "42",
		},
		{
			name:     "int64 input",
			input:    int64(123456789012),
			expected: "123456789012",
		},
		{
			name:     "float64 input",
			input:    3.14159,
			expected: "3.14159",
		},
		{
			name:     "bool true",
			input:    true,
			expected: "true",
		},
		{
			name:     "bool false",
			input:    false,
			expected: "false",
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCELEvaluatorSingleton(t *testing.T) {
	// Reset the singleton for testing
	celEvaluatorOnce = sync.Once{}
	globalCELEvaluator = nil
	celInitErr = nil

	// Get the evaluator
	eval1, err := GetCELEvaluator()
	if err != nil {
		t.Fatalf("failed to get CEL evaluator: %v", err)
	}
	if eval1 == nil {
		t.Fatal("CEL evaluator is nil")
	}

	// Get the evaluator again - should be the same instance
	eval2, err := GetCELEvaluator()
	if err != nil {
		t.Fatalf("failed to get CEL evaluator on second call: %v", err)
	}
	if eval1 != eval2 {
		t.Error("CEL evaluator singleton returned different instances")
	}
}
