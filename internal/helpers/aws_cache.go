package helpers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"reflect"
)

var NonCacheableOperations = []string{
	"STS.GetCallerIdentity",
}

func isCacheable(service, operation string) bool {

	for _, nonCacheableOperation := range NonCacheableOperations {
		if fmt.Sprintf("%s.%s", service, operation) == nonCacheableOperation {
			return false
		}
	}

	return true
}

// saveResponseToFile writes the HTTP response to a specified file.
func saveResponseToFile(resp *http.Response, filename string) error {
	// Dump the response
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return fmt.Errorf("failed to dump response: %v", err)
	}

	// Write to file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("failed to close file: %v", err)
		}
	}(file)

	_, err = file.Write(respBytes)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

// loadResponseFromFile reads an HTTP response from a specified file.
func loadResponseFromFile(filename string) (*http.Response, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("failed to close file: %v", err)
		}
	}(file)

	// Read the file content
	reader := bufio.NewReader(file)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return resp, nil
}

// getCachePath constructs the file path for the cache based on the cache directory and key.
func getCachePath(CacheDir string, key string) string {
	return filepath.Join(CacheDir, key+".cache")
}

// generateCacheKey creates a unique cache key based on the service, operation, and parameters.
func generateCacheKey(service, operation string, params interface{}) string {
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Sprintf("%s-%s", service, operation)
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%s-%s-%s", service, operation, hex.EncodeToString(hash[:]))
}

// CacheConfigs holds cache configuration details.
type CacheConfigs struct {
	CachePath string
	CacheKey  string
	Enabled   bool
	Cacheable bool
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
	if v, ok := GetCacheConfig(ctx, "cache_config"); ok {
		fmt.Printf("Retrieved value: %+v\n", v)
		if !v.Enabled || !v.Cacheable {
			fmt.Printf("Cache bypassed. Enabled: %t; Cacheable: %t", v.Enabled, v.Cacheable)
			return handler.HandleDeserialize(ctx, input)
		}
		resp, err := loadResponseFromFile(v.CachePath)
		if err != nil {
			fmt.Printf("Error loading response: %v\n", err)
			output, metadata, err := handler.HandleDeserialize(ctx, input)
			if err != nil {
				return output, metadata, err
			}
			fmt.Printf("Got Response\n")
			fmt.Printf("Output: %#v\n", output)
			fmt.Printf("Metadata: %#v\n", metadata)
			fmt.Printf("Error: %v\n", err)
			if resp, ok := output.RawResponse.(*smithyhttp.Response); ok {
				standardResp := resp.Response
				saveErr := saveResponseToFile(standardResp, v.CachePath)
				if saveErr != nil {
					fmt.Printf("Error saving response: %v\n", saveErr)
				} else {
					fmt.Printf("Saved response to file %s\n", v.CachePath)
				}
			} else {
				fmt.Printf("Raw response is not an HTTP response\n")
			}
			return output, metadata, err
		} else {
			// TODO: check if cache expired
			output := middleware.DeserializeOutput{RawResponse: &smithyhttp.Response{Response: resp}, Result: nil}
			fmt.Printf("Using cache file: %s\n", v.CacheKey)
			return output, middleware.Metadata{}, err
		}
	} else {
		fmt.Println("Value not found in context")
		return handler.HandleDeserialize(ctx, input)
	}
})

// CachePrep is a middleware that prepares caching by setting up the context with cache configuration.
var CachePrep = middleware.InitializeMiddlewareFunc("CachePrep", func(ctx context.Context, input middleware.InitializeInput, handler middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
	// Extract service and operation information using awsmiddleware helpers
	service := awsmiddleware.GetServiceID(ctx)
	operation := awsmiddleware.GetOperationName(ctx)

	fmt.Printf("Service: %s\n", service)
	fmt.Printf("Operation: %s\n", operation)

	// Skip if we couldn't determine service or operation
	if service == "" || operation == "" {
		fmt.Sprintf("Could not determine service (%s) or operation (%s), params: %+v",
			service, operation, input.Parameters)
		return handler.HandleInitialize(ctx, input)
	}

	fmt.Sprintf("Processing request for service: %s, operation: %s", service, operation)
	// Generate cache key and get cache file path
	cacheKey := generateCacheKey(service, operation, input.Parameters)
	cachePath := getCachePath("/tmp", cacheKey)

	CacheConfig := CacheConfigs{
		CachePath: cachePath,
		CacheKey:  cacheKey,
		Enabled:   true,
		Cacheable: isCacheable(service, operation),
	}
	ctx = SetCacheConfig(ctx, "cache_config", CacheConfig)
	return handler.HandleInitialize(ctx, input)
})
