package helpers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/praetorian-inc/nebula/internal/logs"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"reflect"
)

var (
	NonCacheableOperations = []string{
		"STS.GetCallerIdentity",
	}
	logger = logs.NewLogger()
)

func isCacheable(service, operation string) bool {
	for _, nonCacheableOperation := range NonCacheableOperations {
		if fmt.Sprintf("%s.%s", service, operation) == nonCacheableOperation {
			return false
		}
	}
	return true
}

func dumpResponse(resp *http.Response) ([]byte, error) {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

func saveResponseFromDumpToFile(dump []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		logger.Error("Failed to create file", "filename", filename, "error", err)
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close file", "filename", filename, "error", err)
		}
	}()

	_, err = file.Write(dump)
	if err != nil {
		logger.Error("Failed to write to file", "filename", filename, "error", err)
		return fmt.Errorf("failed to write to file: %v", err)
	}

	logger.Info("Response saved to file", "filename", filename)
	return nil
}

// saveResponseToFile writes the HTTP response to a specified file.
func saveResponseToFile(resp *http.Response, filename string) error {
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logger.Error("Failed to dump response", "error", err)
		return fmt.Errorf("failed to dump response: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		logger.Error("Failed to create file", "filename", filename, "error", err)
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close file", "filename", filename, "error", err)
		}
	}()

	_, err = file.Write(respBytes)
	if err != nil {
		logger.Error("Failed to write to file", "filename", filename, "error", err)
		return fmt.Errorf("failed to write to file: %v", err)
	}

	logger.Info("Response saved to file", "filename", filename)
	return nil
}

// loadResponseFromFile reads an HTTP response from a specified file.
func loadResponseFromFile(filename string) (*http.Response, *os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		logger.Warn("Failed to open file", "filename", filename, "error", err)
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}

	reader := bufio.NewReader(file)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		logger.Error("Failed to read response from file", "filename", filename, "error", err)
		file.Close()
		return nil, nil, fmt.Errorf("failed to read response: %v", err)
	}

	logger.Info("Response loaded from file", "filename", filename)
	return resp, file, nil
}

// getCachePath constructs the file path for the cache based on the cache directory and key.
func getCachePath(CacheDir string, key string) string {
	return filepath.Join(CacheDir, key+".cache")
}

// generateCacheKey creates a unique cache key based on the service, operation, and parameters.
func generateCacheKey(arn, service, operation string, params interface{}) string {
	data, err := json.Marshal(params)
	if err != nil {
		logger.Error("Failed to marshal parameters", "error", err)
		return fmt.Sprintf("%s-%s-%s", service, operation, arn)
	}

	combined := fmt.Sprintf("%s-%s-%s-%s", arn, service, operation, string(data))
	hash := sha256.Sum256([]byte(combined))

	logger.Debug("Generated cache key", "cacheKey", hex.EncodeToString(hash[:]))
	return hex.EncodeToString(hash[:])
}

// CacheConfigs holds cache configuration details.
type CacheConfigs struct {
	CachePath    string
	CacheKey     string
	Enabled      bool
	Cacheable    bool
	Fd           *os.File
	Identity     sts.GetCallerIdentityOutput
	ResponseDump []byte
}

// SetCacheConfig adds a CacheConfigs to the context.
func SetCacheConfig(ctx context.Context, key string, value CacheConfigs) context.Context {
	return context.WithValue(ctx, key, value)
}

// GetCacheConfig retrieves a CacheConfigs from the context.
func GetCacheConfig(ctx context.Context, key string) (CacheConfigs, bool) {
	v, ok := ctx.Value(key).(CacheConfigs)
	return v, ok
}

// SetCacheConfigMeta adds a CacheConfigs to the middleware metadata.
func SetCacheConfigMeta(metadata *middleware.Metadata, key string, value CacheConfigs) {
	metadata.Set(key, value)
}

// GetCacheConfigMeta retrieves a CacheConfigs from the middleware metadata.
func GetCacheConfigMeta(metadata middleware.Metadata, key string) (v CacheConfigs) {
	v, _ = metadata.Get(key).(CacheConfigs)
	return v
}

var testMiddleware = middleware.InitializeMiddlewareFunc("TestMiddleware", func(ctx context.Context, input middleware.InitializeInput, handler middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {

	fmt.Println("\n=== Initialize Debug ===")

	// Print Context details
	fmt.Println("\n=== Context Details ===")
	fmt.Printf("Context: %#v\n", ctx)

	// Print Input details
	fmt.Println("\n=== Input Details ===")
	fmt.Printf("Parameters Type: %T\n", input.Parameters)
	if input.Parameters != nil {
		v := reflect.ValueOf(input.Parameters).Elem()
		t := v.Type()

		fmt.Println("Parameters Content:")
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldName := t.Field(i).Name

			// Handle string pointers
			if field.Kind() == reflect.Pointer && field.Type().Elem().Kind() == reflect.String {
				if !field.IsNil() {
					fmt.Printf("  %s: %q\n", fieldName, field.Elem().String())
				} else {
					fmt.Printf("  %s: nil\n", fieldName)
				}
				continue
			}

			// Handle other types
			if field.CanInterface() {
				fmt.Printf("  %s: %#v\n", fieldName, field.Interface())
			}
		}
	}

	// Print Handler details
	fmt.Println("\n=== Handler Details ===")
	handlerValue := reflect.ValueOf(handler)
	fmt.Printf("Handler Type: %T\n", handler)

	if handlerValue.Kind() == reflect.Struct {
		for i := 0; i < handlerValue.NumField(); i++ {
			field := handlerValue.Field(i)
			fieldType := handlerValue.Type().Field(i)
			if field.CanInterface() {
				fmt.Printf("Field: %s, Type: %s, Value: %#v\n",
					fieldType.Name, field.Type(), field.Interface())
			} else {
				fmt.Printf("Field: %s, Type: %s (unexported)\n",
					fieldType.Name, field.Type())
			}
		}
	}

	// Execute the handler and save results
	output, metadata, err := handler.HandleInitialize(ctx, input)

	// Print the results
	fmt.Println("\n=== Handler Output ===")
	fmt.Printf("Output: %#v\n", output)
	fmt.Printf("Metadata: %#v\n", metadata)
	fmt.Printf("Error: %v\n", err)

	return output, metadata, err
})

var testMiddleware2 = middleware.DeserializeMiddlewareFunc("TestMiddleware2", func(ctx context.Context, input middleware.DeserializeInput, handler middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	fmt.Println("\n=== Deserialize Debug ===")

	// Print Context details
	fmt.Println("\n=== Context Details ===")
	fmt.Printf("Context: %#v\n", ctx)

	// Print Input details
	fmt.Println("\n=== Input Details ===")
	fmt.Printf("Parameters Type: %T\n", input)

	// Execute the handler and save results
	output, metadata, err := handler.HandleDeserialize(ctx, input)

	fmt.Println("\n=== Output Details ===")

	if err != nil {
		fmt.Printf("Error occurred: %v\n", err)
	}
	fmt.Printf("Output: %#v\n", output)
	fmt.Printf("Metadata: %#v\n", metadata)
	fmt.Printf("Error: %v\n", err)

	resp := awsmiddleware.GetRawResponse(metadata)
	fmt.Printf("resp: %#v\n", resp)

	if resp, ok := output.RawResponse.(*smithyhttp.Response); ok {
		standardResp := resp.Response
		respBytes, dumpErr := httputil.DumpResponse(standardResp, true)
		if dumpErr != nil {
			fmt.Printf("Failed to dump response: %v\n", dumpErr)
		} else {
			fmt.Printf("HTTP Response:\n%s\n", string(respBytes))
		}
	}

	// Access the raw HTTP response
	if httpResp, ok := resp.(*http.Response); ok {
		respBytes, dumpErr := httputil.DumpResponse(httpResp, true)
		if dumpErr != nil {
			fmt.Printf("Failed to dump response: %v\n", dumpErr)
		} else {
			fmt.Printf("HTTP Response:\n%s\n", string(respBytes))
		}
	} else {
		fmt.Println("Raw response is not an HTTP response")
		fmt.Printf("Raw response type: %T\n", resp)
		fmt.Printf("Raw response: %v\n", resp)
		fmt.Printf("Raw response2: %s\n", resp)
	}

	return output, metadata, err
})

// CacheOps is a middleware that handles caching operations during the deserialization phase.
var CacheOps = middleware.DeserializeMiddlewareFunc("CacheOps", func(ctx context.Context, input middleware.DeserializeInput, handler middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	// Retrieve cache configuration from context
	if v, ok := GetCacheConfig(ctx, "cache_config"); ok {
		logger.Debug("Retrieved cache configuration", "config", v)

		// Check if caching is enabled and the operation is cacheable
		if !v.Enabled || !v.Cacheable {
			logger.Info("Cache bypassed", "enabled", v.Enabled, "cacheable", v.Cacheable)
			return handler.HandleDeserialize(ctx, input)
		}

		// Attempt to load response from cache
		resp, file, err := loadResponseFromFile(v.CachePath)
		if err != nil {
			logger.Warn("Error loading response from cache", "error", err, "cachePath", v.CachePath)

			// Ensure the file is closed if it was opened
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					logger.Error("Failed to close cache file", "error", closeErr, "cachePath", v.CachePath)
				}
			}

			// Proceed with the handler if cache loading fails
			output, metadata, err := handler.HandleDeserialize(ctx, input)
			if err != nil {
				logger.Error("Handler encountered an error", "error", err)
				return output, metadata, err
			}

			logger.Info("Handler processed response", "output", output, "metadata", metadata)

			//Save the response to cache
			if resp, ok := output.RawResponse.(*smithyhttp.Response); ok {
				standardResp := resp.Response
				//if saveErr := saveResponseToFile(standardResp, v.CachePath); saveErr != nil {
				//	logger.Error("Error saving response to cache", "error", saveErr, "cachePath", v.CachePath)
				//} else {
				//	logger.Info("Response saved to cache", "cachePath", v.CachePath)
				//}

				ResponseDump, DumpErr := dumpResponse(standardResp)
				if DumpErr != nil {
					logger.Warn("Error dumping response", "error", DumpErr, "response", resp)
					return output, metadata, err
				}
				v.ResponseDump = ResponseDump
				SetCacheConfigMeta(&metadata, "cache_config", v)

			} else {
				logger.Warn("Raw response is not an HTTP response", "rawResponse", output.RawResponse)
			}

			return output, metadata, err
		}

		// Cache hit: use the cached response
		logger.Info("Using cached response", "cacheKey", v.CacheKey)
		v.Fd = file
		metadata := middleware.Metadata{}
		SetCacheConfigMeta(&metadata, "cache_config", v)
		output := middleware.DeserializeOutput{RawResponse: &smithyhttp.Response{Response: resp}, Result: nil}
		return output, metadata, nil
	}

	// Cache configuration not found in context
	logger.Warn("Cache configuration not found in context")
	return handler.HandleDeserialize(ctx, input)
})

func GetCachePrepWithIdentity(callerIdentity sts.GetCallerIdentityOutput) middleware.InitializeMiddleware {
	return middleware.InitializeMiddlewareFunc("CachePrep", func(ctx context.Context, input middleware.InitializeInput, handler middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		// Extract service and operation information using awsmiddleware helpers
		service := awsmiddleware.GetServiceID(ctx)
		operation := awsmiddleware.GetOperationName(ctx)

		logger.Debug("Extracted service and operation", "service", service, "operation", operation)

		// Skip if we couldn't determine service or operation
		if service == "" || operation == "" {
			logger.Warn("Could not determine service or operation", "service", service, "operation", operation, "parameters", input.Parameters)
			return handler.HandleInitialize(ctx, input)
		}

		logger.Info("Processing request", "service", service, "operation", operation)

		// Generate cache key and get cache file path
		cacheKey := generateCacheKey(*callerIdentity.Arn, service, operation, input.Parameters)
		cachePath := getCachePath(os.TempDir(), cacheKey)

		cacheConfig := CacheConfigs{
			CachePath:    cachePath,
			CacheKey:     cacheKey,
			Enabled:      true,
			Cacheable:    isCacheable(service, operation),
			Identity:     callerIdentity,
			ResponseDump: nil,
		}
		ctx = SetCacheConfig(ctx, "cache_config", cacheConfig)

		output, metadata, err := handler.HandleInitialize(ctx, input)
		if err != nil {
			logger.Error("Handler encountered an error", "error", err)
			return output, metadata, err
		}

		if cacheConfig.Enabled && cacheConfig.Cacheable {
			v := GetCacheConfigMeta(metadata, "cache_config")
			if v.Fd != nil {
				if err := v.Fd.Close(); err != nil {
					logger.Error("Failed to close file", "error", err)
				} else {
					logger.Debug("Closed file successfully")
				}
			}
			if v.ResponseDump != nil {
				SaveErr := saveResponseFromDumpToFile(v.ResponseDump, v.CachePath)
				if SaveErr != nil {
					logger.Error("Failed to save response from cache", "error", SaveErr)
				}
			}
		}

		// Optionally log caller identity details
		// logger.Debug("Caller Identity", "Account", *callerIdentity.Account, "Arn", *callerIdentity.Arn, "UserId", *callerIdentity.UserId)

		return output, metadata, nil
	})
}
