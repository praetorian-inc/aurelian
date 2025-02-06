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
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	NonCacheableOperations = []string{
		"STS.GetCallerIdentity",
	}
	logger          = *logs.NewLogger()
	cacheMaintained = false
	cacheHitCount   int64
	cacheMissCount  int64
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

	logger.Debug("Response saved to file", "filename", filename)
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

	logger.Debug("Response saved to file", "filename", filename)
	return nil
}

// loadResponseFromFile reads an HTTP response from a specified file.
func loadResponseFromFile(filename string) (*http.Response, *os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		logger.Debug("Failed to open file", "filename", filename, "error", err)
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}

	reader := bufio.NewReader(file)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		logger.Error("Failed to read response from file", "filename", filename, "error", err)
		file.Close()
		return nil, nil, fmt.Errorf("failed to read response: %v", err)
	}

	logger.Debug("Response loaded from file", "filename", filename)
	return resp, file, nil
}

// getCachePath constructs the file path for the cache based on the cache directory and key.
func getCachePath(CacheDir string, key string, ext string) string {
	return filepath.Join(CacheDir, key+ext)
}

// generateCacheKey creates a unique cache key based on the service, operation, and parameters.
func generateCacheKey(arn, service, region string, operation string, params interface{}) string {
	data, err := json.Marshal(params)
	if err != nil {
		logger.Error("Failed to marshal parameters", "error", err)
		return fmt.Sprintf("%s-%s-%s-%s", service, operation, arn, region)
	}

	combined := fmt.Sprintf("%s-%s-%s-%s-%s", arn, region, service, operation, string(data))
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// CacheConfigs holds cache configuration details.
type CacheConfigs struct {
	CachePath      string
	CacheKey       string
	TTL            int
	Enabled        bool
	Cacheable      bool
	CacheErrorResp bool
	Fd             *os.File
	Identity       sts.GetCallerIdentityOutput
	ResponseDump   []byte
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

// CacheOps is a middleware that handles caching operations during the deserialization phase.
var CacheOps = middleware.DeserializeMiddlewareFunc("CacheOps", func(ctx context.Context, input middleware.DeserializeInput, handler middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	// Retrieve cache configuration from context
	if v, ok := GetCacheConfig(ctx, "cache_config"); ok {
		logger.Debug("Retrieved cache configuration", "config", v)

		// Check if caching is enabled and the operation is cacheable
		if !v.Enabled || !v.Cacheable {
			logger.Debug("Deserialize Cache bypassed", "enabled", v.Enabled, "cacheable", v.Cacheable)
			return handler.HandleDeserialize(ctx, input)
		}

		// Attempt to load response from cache
		resp, file, err := loadResponseFromFile(v.CachePath)
		if err != nil {
			logger.Debug("Error loading response from cache", "error", err, "cachePath", v.CachePath)

			// Ensure the file is closed if it was opened
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					logger.Error("Failed to close cache file", "error", closeErr, "cachePath", v.CachePath)
				}
			}

			// Cache miss: increment miss counter
			atomic.AddInt64(&cacheMissCount, 1)

			// Proceed with the handler if cache loading fails
			output, metadata, err := handler.HandleDeserialize(ctx, input)
			if err != nil {
				logger.Debug("Handler encountered an error", "error", err)
				//return output, metadata, err
			}

			logger.Debug("Handler processed response", "output", output, "metadata", metadata)

			//Save the response to cache
			if resp, ok := output.RawResponse.(*smithyhttp.Response); ok {
				standardResp := resp.Response
				//if saveErr := saveResponseToFile(standardResp, v.CachePath); saveErr != nil {
				//	logger.Error("Error saving response to cache", "error", saveErr, "cachePath", v.CachePath)
				//} else {
				//	logger.Debug("Response saved to cache", "cachePath", v.CachePath)
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

		// Cache hit: increment hit counter
		atomic.AddInt64(&cacheHitCount, 1)

		// Cache hit: use the cached response
		logger.Debug("Using cached response", "cacheKey", v.CacheKey)
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

func GetCachePrepWithIdentity(callerIdentity sts.GetCallerIdentityOutput, opts []*types.Option) middleware.InitializeMiddleware {
	cacheDir := options.GetOptionByName(options.AwsCacheDirOpt.Name, opts).Value
	cacheExt := options.GetOptionByName(options.AwsCacheExtOpt.Name, opts).Value
	cacheTTL := options.GetOptionByName(options.AwsCacheTTLOpt.Name, opts).Value
	cacheError := options.GetOptionByName(options.AwsCacheErrorRespOpt.Name, opts).Value
	TTL, err := strconv.Atoi(cacheTTL)
	if err != nil {
		logger.Error("Could not determine cache TTL", "error", err)
		logger.Warn("Fallback to default TTL of 3600")
		TTL = 3600
	}
	CacheDisabled := options.GetOptionByName(options.AwsDisableCacheOpt.Name, opts).Value
	CacheEnabled, err := strconv.ParseBool(CacheDisabled)
	if err != nil {
		logger.Error("Could not determine cache enabled", "error", err)
		logger.Warn("Fallback to enable cache")
		CacheEnabled = true
	} else { // Mapping from CacheDisabled to CacheEnabled
		CacheEnabled = !CacheEnabled
	}
	CacheErrorResp, err := strconv.ParseBool(cacheError)
	if err != nil {
		logger.Error("Could not determine cache error response", "error", err)
		logger.Warn("Fallback to Not cache error response")
		CacheErrorResp = false
	}
	if !(CacheEnabled) {
		logger.Debug("Config Cache bypassed", "enabled", CacheEnabled, "cacheErrorResp", CacheErrorResp)
	}

	return middleware.InitializeMiddlewareFunc("CachePrep", func(ctx context.Context, input middleware.InitializeInput, handler middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		// Extract service and operation information using awsmiddleware helpers
		service := awsmiddleware.GetServiceID(ctx)
		operation := awsmiddleware.GetOperationName(ctx)
		region := awsmiddleware.GetRegion(ctx)

		// Skip if we couldn't determine service, operation, or region
		if service == "" || operation == "" || region == "" {
			logger.Warn("Could not determine service, operation, or region",
				"service", service, "operation", operation, "region", region, "parameters", input.Parameters)
			return handler.HandleInitialize(ctx, input)
		}

		logger.Debug("Processing request", "service", service, "operation", operation, "region", region)

		// Generate cache key and get cache file path
		cacheKey := generateCacheKey(*callerIdentity.Arn, service, region, operation, input.Parameters)

		logger.Debug("CacheKey computed", "cacheKey", cacheKey)

		cachePath := getCachePath(cacheDir, cacheKey, cacheExt)

		cacheConfig := CacheConfigs{
			CachePath:      cachePath,
			CacheKey:       cacheKey,
			Enabled:        CacheEnabled,
			CacheErrorResp: CacheErrorResp,
			TTL:            TTL,
			Cacheable:      isCacheable(service, operation),
			Identity:       callerIdentity,
			ResponseDump:   nil,
		}
		ctx = SetCacheConfig(ctx, "cache_config", cacheConfig)

		output, metadata, err := handler.HandleInitialize(ctx, input)
		if err != nil {
			logger.Debug("Handler encountered an error", "error", err)
			if !(cacheConfig.Enabled && cacheConfig.Cacheable && cacheConfig.CacheErrorResp) {
				logger.Debug("Cache bypassed", "enabled", cacheConfig.Enabled, "cacheable", cacheConfig.Cacheable, "cacheErrorResp", cacheConfig.CacheErrorResp)
				return output, metadata, err
			}
		}

		if cacheConfig.Enabled && cacheConfig.Cacheable {
			v := GetCacheConfigMeta(metadata, "cache_config")
			if v.Fd != nil {
				if fdErr := v.Fd.Close(); fdErr != nil {
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
			} else {
				logger.Debug("ResponseDump is nil")
			}
		} else {
			logger.Debug("Cache bypassed", "enabled", cacheConfig.Enabled, "cacheable", cacheConfig.Cacheable, "cacheErrorResp", cacheConfig.CacheErrorResp)
		}

		// Optionally log caller identity details
		// logger.Debug("Caller Identity", "Account", *callerIdentity.Account, "Arn", *callerIdentity.Arn, "UserId", *callerIdentity.UserId)

		return output, metadata, err
	})
}

// CleanupCacheFiles scans the cache directory and removes expired cache files.
func CleanupCacheFiles(cacheDir string, ttl int, cacheExt string) {
	clanUpCount := 0
	total := 0
	files, err := os.ReadDir(cacheDir)
	if err != nil {
		logger.Error("Failed to read cache directory", "cacheDir", cacheDir, "error", err)
		return
	}

	expirationTime := time.Duration(ttl) * time.Second
	currentTime := time.Now()

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), cacheExt) {
			continue
		}
		total++

		filePath := filepath.Join(cacheDir, file.Name())

		info, err := os.Stat(filePath)
		if err != nil {
			logger.Warn("Failed to get file info", "filePath", filePath, "error", err)
			continue
		}

		if currentTime.Sub(info.ModTime()) > expirationTime {
			logger.Debug("Cache cleanup", "filePath", filePath, "currentTime", currentTime, "fileModTime", info.ModTime(), "delta", currentTime.Sub(info.ModTime()), "expirationTime", expirationTime)
			err := os.Remove(filePath)
			if err != nil {
				logger.Warn("Failed to delete expired cache file", "filePath", filePath, "error", err)
			} else {
				clanUpCount++
				logger.Debug("Deleted expired cache file", "filePath", filePath)
			}
		} else {
			logger.Debug("Cache persisted", "filePath", filePath, "currentTime", currentTime, "fileModTime", info.ModTime(), "delta", currentTime.Sub(info.ModTime()), "expirationTime", expirationTime)
		}
	}
	logger.Info("Cache cleanup processed", "total", total, "clanUpCount", clanUpCount)
}

// InitCacheCleanup runs once at the program start to clean up expired cache files.
func InitCacheCleanup(opts []*types.Option) {
	cacheDir := options.GetOptionByName(options.AwsCacheDirOpt.Name, opts).Value
	cacheExt := options.GetOptionByName(options.AwsCacheExtOpt.Name, opts).Value
	cacheTTL := options.GetOptionByName(options.AwsCacheTTLOpt.Name, opts).Value

	ttl, err := strconv.Atoi(cacheTTL)
	if err != nil {
		logger.Error("Could not determine cache TTL", "error", err)
		logger.Warn("Fallback to default TTL of 3600")
		ttl = 3600
	}

	CleanupCacheFiles(cacheDir, ttl, cacheExt)
}

func GetCacheHitCount() int64 {
	return atomic.LoadInt64(&cacheHitCount)
}

func GetCacheMissCount() int64 {
	return atomic.LoadInt64(&cacheMissCount)
}

func SetAWSCacheLogger(newLogger *slog.Logger) {
	logger = *newLogger
}
