package ratelimit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

// CELEvaluator provides CEL expression evaluation for rate limit key and cost extraction
type CELEvaluator struct {
	mu sync.RWMutex

	// Compiled CEL programs cache
	// Key: expression string, Value: compiled cel.Program
	programCache map[string]cel.Program

	// CEL environment for key extraction (returns string)
	keyEnv *cel.Env

	// CEL environment for cost extraction (returns numeric)
	costEnv *cel.Env
}

// globalCELEvaluator is a singleton CEL evaluator instance
var (
	globalCELEvaluator *CELEvaluator
	celEvaluatorOnce   sync.Once
	celInitErr         error
)

// GetCELEvaluator returns the singleton CEL evaluator instance
func GetCELEvaluator() (*CELEvaluator, error) {
	celEvaluatorOnce.Do(func() {
		evaluator, err := newCELEvaluator()
		if err != nil {
			celInitErr = err
			return
		}
		globalCELEvaluator = evaluator
	})
	if celInitErr != nil {
		return nil, celInitErr
	}
	return globalCELEvaluator, nil
}

// newCELEvaluator creates a new CEL evaluator with environments for both key and cost extraction
func newCELEvaluator() (*CELEvaluator, error) {
	keyEnv, err := createKeyExtractionEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create key extraction CEL environment: %w", err)
	}

	costEnv, err := createCostExtractionEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create cost extraction CEL environment: %w", err)
	}

	return &CELEvaluator{
		programCache: make(map[string]cel.Program),
		keyEnv:       keyEnv,
		costEnv:      costEnv,
	}, nil
}

// createKeyExtractionEnv creates a CEL environment for key extraction expressions
// Key extraction expressions must return a string
func createKeyExtractionEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Request context variables
		cel.Variable("request.Headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("request.Body", cel.BytesType),
		cel.Variable("request.BodyString", cel.StringType),
		cel.Variable("request.Path", cel.StringType),
		cel.Variable("request.Method", cel.StringType),
		cel.Variable("request.Metadata", cel.MapType(cel.StringType, cel.DynType)),
		// API context variables
		cel.Variable("api.Name", cel.StringType),
		cel.Variable("api.Version", cel.StringType),
		cel.Variable("api.Context", cel.StringType),
		cel.Variable("api.Id", cel.StringType),
		// Route info
		cel.Variable("route.Name", cel.StringType),
		// Custom jsonPath function for extracting values from JSON strings
		jsonPathStringFunction(),
	)
}

// createCostExtractionEnv creates a CEL environment for cost extraction expressions
// Cost extraction expressions must return a numeric value (int or double)
func createCostExtractionEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Request context variables (for request_cel type)
		cel.Variable("request.Headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("request.Body", cel.BytesType),
		cel.Variable("request.BodyString", cel.StringType),
		cel.Variable("request.Path", cel.StringType),
		cel.Variable("request.Method", cel.StringType),
		cel.Variable("request.Metadata", cel.MapType(cel.StringType, cel.DynType)),
		// Response context variables (for response_cel type)
		cel.Variable("response.Headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("response.Body", cel.BytesType),
		cel.Variable("response.BodyString", cel.StringType),
		cel.Variable("response.Status", cel.IntType),
		// API context variables
		cel.Variable("api.Name", cel.StringType),
		cel.Variable("api.Version", cel.StringType),
		cel.Variable("api.Context", cel.StringType),
		cel.Variable("api.Id", cel.StringType),
		// Custom jsonPath function for extracting values from JSON strings
		jsonPathStringFunction(),
		jsonPathIntFunction(),
		jsonPathDoubleFunction(),
	)
}

// EvaluateKeyExpression evaluates a CEL expression for key extraction from request context
// Returns the extracted key string or an error
func (e *CELEvaluator) EvaluateKeyExpression(expression string, ctx *policy.RequestContext, routeName string) (string, error) {
	program, err := e.getOrCompileKeyProgram(expression)
	if err != nil {
		return "", fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	// Build evaluation context
	evalCtx := buildKeyEvalContext(ctx, routeName)

	// Evaluate
	result, _, err := program.Eval(evalCtx)
	if err != nil {
		slog.Debug("CEL key extraction evaluation failed", "expression", expression, "error", err)
		return "", fmt.Errorf("CEL evaluation failed: %w", err)
	}

	// Convert to string
	strResult, ok := result.Value().(string)
	if !ok {
		return "", fmt.Errorf("CEL expression must return string, got %T", result.Value())
	}

	return strResult, nil
}

// EvaluateRequestCostExpression evaluates a CEL expression for cost extraction from request context
// Returns the extracted cost value or an error
func (e *CELEvaluator) EvaluateRequestCostExpression(expression string, ctx *policy.RequestContext) (float64, error) {
	program, err := e.getOrCompileCostProgram(expression)
	if err != nil {
		return 0, fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	// Build evaluation context for request phase
	evalCtx := buildRequestCostEvalContext(ctx)

	// Evaluate
	result, _, err := program.Eval(evalCtx)
	if err != nil {
		slog.Debug("CEL request cost extraction evaluation failed", "expression", expression, "error", err)
		return 0, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	// Convert to float64
	return toFloat64(result.Value())
}

// EvaluateResponseCostExpression evaluates a CEL expression for cost extraction from response context
// Returns the extracted cost value or an error
func (e *CELEvaluator) EvaluateResponseCostExpression(expression string, ctx *policy.ResponseContext) (float64, error) {
	program, err := e.getOrCompileCostProgram(expression)
	if err != nil {
		return 0, fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	// Build evaluation context for response phase
	evalCtx := buildResponseCostEvalContext(ctx)

	// Evaluate
	result, _, err := program.Eval(evalCtx)
	if err != nil {
		slog.Debug("CEL response cost extraction evaluation failed", "expression", expression, "error", err)
		return 0, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	// Convert to float64
	return toFloat64(result.Value())
}

// buildKeyEvalContext builds the CEL evaluation context for key extraction
func buildKeyEvalContext(ctx *policy.RequestContext, routeName string) map[string]interface{} {
	// Convert headers to map[string][]string for CEL
	headers := make(map[string][]string)
	if ctx.Headers != nil {
		ctx.Headers.Iterate(func(key string, values []string) {
			headers[key] = values
		})
	}

	// Build metadata map
	metadata := make(map[string]interface{})
	if ctx.Metadata != nil {
		for k, v := range ctx.Metadata {
			metadata[k] = v
		}
	}

	// Get body content for jsonPath functions
	var bodyBytes []byte
	var bodyString string
	if ctx.Body != nil && ctx.Body.Present && ctx.Body.Content != nil {
		bodyBytes = ctx.Body.Content
		bodyString = string(bodyBytes)
	}

	return map[string]interface{}{
		"request.Headers":    headers,
		"request.Body":       bodyBytes,
		"request.BodyString": bodyString,
		"request.Path":       ctx.Path,
		"request.Method":     ctx.Method,
		"request.Metadata":   metadata,
		"api.Name":           ctx.APIName,
		"api.Version":        ctx.APIVersion,
		"api.Context":        ctx.APIContext,
		"api.Id":             ctx.APIId,
		"route.Name":         routeName,
	}
}

// buildRequestCostEvalContext builds the CEL evaluation context for request-phase cost extraction
func buildRequestCostEvalContext(ctx *policy.RequestContext) map[string]interface{} {
	// Convert headers to map[string][]string for CEL
	headers := make(map[string][]string)
	if ctx.Headers != nil {
		ctx.Headers.Iterate(func(key string, values []string) {
			headers[key] = values
		})
	}

	// Build metadata map
	metadata := make(map[string]interface{})
	if ctx.Metadata != nil {
		for k, v := range ctx.Metadata {
			metadata[k] = v
		}
	}

	// Get body content
	var bodyBytes []byte
	var bodyString string
	if ctx.Body != nil && ctx.Body.Present && ctx.Body.Content != nil {
		bodyBytes = ctx.Body.Content
		bodyString = string(bodyBytes)
	}

	return map[string]interface{}{
		"request.Headers":    headers,
		"request.Body":       bodyBytes,
		"request.BodyString": bodyString,
		"request.Path":       ctx.Path,
		"request.Method":     ctx.Method,
		"request.Metadata":   metadata,
		// Response variables are empty during request phase
		"response.Headers":    map[string][]string{},
		"response.Body":       []byte{},
		"response.BodyString": "",
		"response.Status":     int64(0),
		"api.Name":            ctx.APIName,
		"api.Version":         ctx.APIVersion,
		"api.Context":         ctx.APIContext,
		"api.Id":              ctx.APIId,
	}
}

// buildResponseCostEvalContext builds the CEL evaluation context for response-phase cost extraction
func buildResponseCostEvalContext(ctx *policy.ResponseContext) map[string]interface{} {
	// Convert request headers to map[string][]string for CEL
	requestHeaders := make(map[string][]string)
	if ctx.RequestHeaders != nil {
		ctx.RequestHeaders.Iterate(func(key string, values []string) {
			requestHeaders[key] = values
		})
	}

	// Convert response headers to map[string][]string for CEL
	responseHeaders := make(map[string][]string)
	if ctx.ResponseHeaders != nil {
		ctx.ResponseHeaders.Iterate(func(key string, values []string) {
			responseHeaders[key] = values
		})
	}

	// Build metadata map
	metadata := make(map[string]interface{})
	if ctx.Metadata != nil {
		for k, v := range ctx.Metadata {
			metadata[k] = v
		}
	}

	// Get request body content
	var requestBodyBytes []byte
	var requestBodyString string
	if ctx.RequestBody != nil && ctx.RequestBody.Present && ctx.RequestBody.Content != nil {
		requestBodyBytes = ctx.RequestBody.Content
		requestBodyString = string(requestBodyBytes)
	}

	// Get response body content
	var responseBodyBytes []byte
	var responseBodyString string
	if ctx.ResponseBody != nil && ctx.ResponseBody.Present && ctx.ResponseBody.Content != nil {
		responseBodyBytes = ctx.ResponseBody.Content
		responseBodyString = string(responseBodyBytes)
	}

	return map[string]interface{}{
		"request.Headers":     requestHeaders,
		"request.Body":        requestBodyBytes,
		"request.BodyString":  requestBodyString,
		"request.Path":        ctx.RequestPath,
		"request.Method":      ctx.RequestMethod,
		"request.Metadata":    metadata,
		"response.Headers":    responseHeaders,
		"response.Body":       responseBodyBytes,
		"response.BodyString": responseBodyString,
		"response.Status":     int64(ctx.ResponseStatus),
		"api.Name":            ctx.APIName,
		"api.Version":         ctx.APIVersion,
		"api.Context":         ctx.APIContext,
		"api.Id":              ctx.APIId,
	}
}

// toFloat64 converts a CEL result value to float64
func toFloat64(val interface{}) (float64, error) {
	switch v := val.(type) {
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("CEL expression must return numeric value, got %T", val)
	}
}

// jsonPathStringFunction creates a CEL function that extracts a string value from JSON using JSONPath
// Usage: jsonPath(jsonString, "$.path.to.value") -> string
// This function can be used with request.BodyString or response.BodyString to extract values
func jsonPathStringFunction() cel.EnvOption {
	return cel.Function("jsonPath",
		cel.Overload("jsonPath_string_string",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.StringType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				jsonStr, ok := lhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPath: first argument must be a string")
				}
				path, ok := rhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPath: second argument must be a string")
				}

				result, err := extractJSONPathValue([]byte(jsonStr), path)
				if err != nil {
					slog.Debug("jsonPath extraction failed", "path", path, "error", err)
					return types.NewErr("jsonPath extraction failed: %v", err)
				}

				// Convert to string
				switch v := result.(type) {
				case string:
					return types.String(v)
				case float64:
					return types.String(strconv.FormatFloat(v, 'f', -1, 64))
				case int:
					return types.String(strconv.Itoa(v))
				case int64:
					return types.String(strconv.FormatInt(v, 10))
				case bool:
					return types.String(strconv.FormatBool(v))
				default:
					// Try to marshal as JSON for complex types
					b, err := json.Marshal(v)
					if err != nil {
						return types.NewErr("jsonPath: cannot convert result to string: %T", v)
					}
					return types.String(string(b))
				}
			}),
		),
	)
}

// jsonPathIntFunction creates a CEL function that extracts an integer value from JSON using JSONPath
// Usage: jsonPathInt(jsonString, "$.path.to.value") -> int
// This function can be used to extract numeric values for cost extraction
func jsonPathIntFunction() cel.EnvOption {
	return cel.Function("jsonPathInt",
		cel.Overload("jsonPathInt_string_string",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.IntType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				jsonStr, ok := lhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPathInt: first argument must be a string")
				}
				path, ok := rhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPathInt: second argument must be a string")
				}

				result, err := extractJSONPathValue([]byte(jsonStr), path)
				if err != nil {
					slog.Debug("jsonPathInt extraction failed", "path", path, "error", err)
					return types.NewErr("jsonPathInt extraction failed: %v", err)
				}

				// Convert to int64
				switch v := result.(type) {
				case float64:
					return types.Int(int64(v))
				case int:
					return types.Int(int64(v))
				case int64:
					return types.Int(v)
				case string:
					i, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						return types.NewErr("jsonPathInt: cannot parse string as int: %s", v)
					}
					return types.Int(i)
				default:
					return types.NewErr("jsonPathInt: cannot convert result to int: %T", v)
				}
			}),
		),
	)
}

// jsonPathDoubleFunction creates a CEL function that extracts a double value from JSON using JSONPath
// Usage: jsonPathDouble(jsonString, "$.path.to.value") -> double
// This function can be used to extract numeric values for cost extraction
func jsonPathDoubleFunction() cel.EnvOption {
	return cel.Function("jsonPathDouble",
		cel.Overload("jsonPathDouble_string_string",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.DoubleType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				jsonStr, ok := lhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPathDouble: first argument must be a string")
				}
				path, ok := rhs.Value().(string)
				if !ok {
					return types.NewErr("jsonPathDouble: second argument must be a string")
				}

				result, err := extractJSONPathValue([]byte(jsonStr), path)
				if err != nil {
					slog.Debug("jsonPathDouble extraction failed", "path", path, "error", err)
					return types.NewErr("jsonPathDouble extraction failed: %v", err)
				}

				// Convert to float64
				switch v := result.(type) {
				case float64:
					return types.Double(v)
				case int:
					return types.Double(float64(v))
				case int64:
					return types.Double(float64(v))
				case string:
					f, err := strconv.ParseFloat(v, 64)
					if err != nil {
						return types.NewErr("jsonPathDouble: cannot parse string as double: %s", v)
					}
					return types.Double(f)
				default:
					return types.NewErr("jsonPathDouble: cannot convert result to double: %T", v)
				}
			}),
		),
	)
}

// extractJSONPathValue extracts a value from JSON using JSONPath
// It uses the SDK's utils.ExtractValueFromJsonpath for consistency
func extractJSONPathValue(jsonData []byte, jsonPath string) (interface{}, error) {
	if len(jsonData) == 0 {
		return nil, fmt.Errorf("empty JSON data")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	value, err := utils.ExtractValueFromJsonpath(data, jsonPath)
	if err != nil {
		return nil, err
	}

	// Handle the case where the result is a slice with a single element
	// This can happen with wildcard queries
	if slice, ok := value.([]interface{}); ok && len(slice) == 1 {
		return slice[0], nil
	}

	return value, nil
}

// toString converts various types to string for CEL
func toString(val interface{}) string {
	if val == nil {
		return ""
	}
	rv := reflect.ValueOf(val)
	switch rv.Kind() {
	case reflect.String:
		return rv.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(rv.Float(), 'f', -1, 64)
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool())
	default:
		// For complex types, try JSON marshaling
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	}
}

// getOrCompileKeyProgram gets a cached program or compiles a new one for key extraction
func (e *CELEvaluator) getOrCompileKeyProgram(expression string) (cel.Program, error) {
	cacheKey := "key:" + expression

	// Check cache first (read lock)
	e.mu.RLock()
	if program, ok := e.programCache[cacheKey]; ok {
		e.mu.RUnlock()
		return program, nil
	}
	e.mu.RUnlock()

	// Compile (write lock)
	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if program, ok := e.programCache[cacheKey]; ok {
		return program, nil
	}

	// Compile expression
	ast, issues := e.keyEnv.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation failed: %w", issues.Err())
	}

	// Create program
	program, err := e.keyEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation failed: %w", err)
	}

	// Cache and return
	e.programCache[cacheKey] = program
	return program, nil
}

// getOrCompileCostProgram gets a cached program or compiles a new one for cost extraction
func (e *CELEvaluator) getOrCompileCostProgram(expression string) (cel.Program, error) {
	cacheKey := "cost:" + expression

	// Check cache first (read lock)
	e.mu.RLock()
	if program, ok := e.programCache[cacheKey]; ok {
		e.mu.RUnlock()
		return program, nil
	}
	e.mu.RUnlock()

	// Compile (write lock)
	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if program, ok := e.programCache[cacheKey]; ok {
		return program, nil
	}

	// Compile expression
	ast, issues := e.costEnv.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation failed: %w", issues.Err())
	}

	// Create program
	program, err := e.costEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation failed: %w", err)
	}

	// Cache and return
	e.programCache[cacheKey] = program
	return program, nil
}
