package cloudcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCloudControlServer creates a fake CloudControl API server for testing.
// The handler function receives the request body (decoded as JSON map) and returns
// a status code and response body (also as a map). The server automatically handles
// AWS SDK signing headers (they're ignored).
func testCloudControlServer(t *testing.T, handler func(body map[string]any) (int, map[string]any)) (*cloudcontrol.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		statusCode, resp := handler(body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	serverURL := server.URL
	client := cloudcontrol.New(cloudcontrol.Options{
		BaseEndpoint: &serverURL,
		HTTPClient:   server.Client(),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
	})

	return client, server
}

// Task 1: IsSkippableError -- Comprehensive Edge Cases
func TestIsSkippableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"TypeNotFoundException", errors.New("TypeNotFoundException: AWS::Foo::Bar"), true},
		{"UnsupportedActionException", errors.New("UnsupportedActionException: not supported"), true},
		{"AccessDeniedException", errors.New("AccessDeniedException: not authorized"), true},
		{"InternalServerError propagated", errors.New("InternalServerError: something broke"), false},
		{"wrapped skip error", fmt.Errorf("list: %w", errors.New("TypeNotFoundException: AWS::Foo")), true},
		{"partial match", errors.New("something TypeNotFoundException something"), true},
		{"empty error message", errors.New(""), false},
		{"generic network error", errors.New("connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSkippableError(tt.err))
		})
	}
}

// Task 2: ListByType -- Single Page Response
func TestListByType_SinglePage(t *testing.T) {
	callCount := 0
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		callCount++
		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": "i-abc123", "Properties": `{"InstanceType":"t2.micro"}`},
				{"Identifier": "i-def456", "Properties": `{"InstanceType":"t3.large"}`},
			},
			// No NextToken = single page
		}
	})

	resources, err := ListByType(context.Background(), client, "AWS::EC2::Instance", "123456789012", "us-east-1")
	require.NoError(t, err)

	assert.Len(t, resources, 2)
	assert.Equal(t, "AWS::EC2::Instance", resources[0].ResourceType)
	assert.Equal(t, "aws", resources[0].Platform)
	assert.Equal(t, "123456789012", resources[0].AccountRef)
	assert.Equal(t, "us-east-1", resources[0].Region)
	assert.Equal(t, 1, callCount, "should make exactly one API call")
}

// Task 3: ListByType -- Pagination
func TestListByType_Pagination(t *testing.T) {
	callCount := 0
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		callCount++
		if callCount == 1 {
			return 200, map[string]any{
				"ResourceDescriptions": []map[string]any{
					{"Identifier": "bucket-1", "Properties": `{}`},
				},
				"NextToken": "page2token",
			}
		}
		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": "bucket-2", "Properties": `{}`},
			},
			// No NextToken = last page
		}
	})

	resources, err := ListByType(context.Background(), client, "AWS::S3::Bucket", "123456789012", "us-east-1")
	require.NoError(t, err)

	assert.Len(t, resources, 2, "should aggregate resources across pages")
	assert.Equal(t, 2, callCount, "should make exactly 2 API calls")
}

// Task 4: ListByType -- API Error
func TestListByType_APIError(t *testing.T) {
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		return 500, map[string]any{
			"__type":  "InternalServiceException",
			"message": "Internal server error",
		}
	})

	resources, err := ListByType(context.Background(), client, "AWS::EC2::Instance", "123456789012", "us-east-1")
	assert.Error(t, err)
	assert.Nil(t, resources)
	assert.Contains(t, err.Error(), "list AWS::EC2::Instance")
}

// Task 5: ListByType -- Context Cancellation
func TestListByType_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		t.Fatal("should not reach server when context is cancelled")
		return 200, nil
	})

	resources, err := ListByType(ctx, client, "AWS::EC2::Instance", "123456789012", "us-east-1")
	assert.Error(t, err)
	assert.Nil(t, resources)
	assert.ErrorIs(t, err, context.Canceled)
}

// Task 6: ListByType -- Empty Response
func TestListByType_EmptyResponse(t *testing.T) {
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{},
		}
	})

	resources, err := ListByType(context.Background(), client, "AWS::EC2::Instance", "123456789012", "us-east-1")
	require.NoError(t, err)
	assert.Empty(t, resources)
}

// Task 7: ListAll -- Concurrent Multi-Type Enumeration
func TestListAll_MultipleTypes(t *testing.T) {
	var mu sync.Mutex
	typesRequested := []string{}

	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		typeName, _ := body["TypeName"].(string)
		mu.Lock()
		typesRequested = append(typesRequested, typeName)
		mu.Unlock()

		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": typeName + "-resource-1", "Properties": `{}`},
			},
		}
	})

	resourceTypes := []string{"AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::Lambda::Function"}
	results, err := ListAll(context.Background(), client, ListOptions{
		ResourceTypes: resourceTypes,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   3,
	})
	require.NoError(t, err)

	// All 3 types should be in results
	assert.Len(t, results, 3)
	assert.Contains(t, results, "AWS::EC2::Instance")
	assert.Contains(t, results, "AWS::S3::Bucket")
	assert.Contains(t, results, "AWS::Lambda::Function")

	// Each type should have 1 resource
	for _, rt := range resourceTypes {
		assert.Len(t, results[rt], 1, "type %s should have 1 resource", rt)
	}

	// All types should have been requested
	assert.ElementsMatch(t, resourceTypes, typesRequested)
}

// Task 8: ListAll -- Skippable Errors Are Logged and Skipped
func TestListAll_SkippableErrorsSkipped(t *testing.T) {
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		typeName, _ := body["TypeName"].(string)

		if typeName == "AWS::Unsupported::Type" {
			return 400, map[string]any{
				"__type":  "UnsupportedActionException",
				"message": "not supported",
			}
		}

		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": "resource-1", "Properties": `{}`},
			},
		}
	})

	resourceTypes := []string{"AWS::EC2::Instance", "AWS::Unsupported::Type", "AWS::S3::Bucket"}
	results, err := ListAll(context.Background(), client, ListOptions{
		ResourceTypes: resourceTypes,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   3,
	})
	require.NoError(t, err)

	// Supported types should be in results
	assert.Contains(t, results, "AWS::EC2::Instance")
	assert.Contains(t, results, "AWS::S3::Bucket")

	// Unsupported type should NOT be in results (skipped, not errored)
	assert.NotContains(t, results, "AWS::Unsupported::Type")
}

// Task 9: ListAll -- Context Cancellation Propagates
func TestListAll_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	callCount := atomic.Int32{}
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		if callCount.Add(1) >= 2 {
			cancel() // Cancel after some work starts
		}
		// Simulate some work
		time.Sleep(50 * time.Millisecond)
		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": "resource-1", "Properties": `{}`},
			},
		}
	})

	resourceTypes := make([]string, 10)
	for i := range resourceTypes {
		resourceTypes[i] = fmt.Sprintf("AWS::Type%d::Resource", i)
	}

	_, err := ListAll(ctx, client, ListOptions{
		ResourceTypes: resourceTypes,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   2,
	})
	assert.Error(t, err)
}

// Task 10: ListAll -- Empty Resource Types Slice
func TestListAll_EmptyResourceTypes(t *testing.T) {
	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		t.Fatal("should not make any API calls for empty resource types")
		return 200, nil
	})

	results, err := ListAll(context.Background(), client, ListOptions{
		ResourceTypes: []string{},
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   3,
	})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// Task 11: ListAll -- Concurrency Limit Respected
func TestListAll_ConcurrencyLimitRespected(t *testing.T) {
	var current, peak atomic.Int32

	client, _ := testCloudControlServer(t, func(body map[string]any) (int, map[string]any) {
		n := current.Add(1)
		defer current.Add(-1)

		// Track peak concurrency
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond) // Simulate API latency

		return 200, map[string]any{
			"ResourceDescriptions": []map[string]any{
				{"Identifier": "resource", "Properties": `{}`},
			},
		}
	})

	resourceTypes := make([]string, 20)
	for i := range resourceTypes {
		resourceTypes[i] = fmt.Sprintf("AWS::Type%d::Resource", i)
	}

	const maxConcurrency = 3
	results, err := ListAll(context.Background(), client, ListOptions{
		ResourceTypes: resourceTypes,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   maxConcurrency,
	})
	require.NoError(t, err)
	assert.Len(t, results, 20)

	// Peak should not exceed the concurrency limit
	assert.LessOrEqual(t, int(peak.Load()), maxConcurrency,
		"peak concurrent requests (%d) should not exceed limit (%d)", peak.Load(), maxConcurrency)
}
