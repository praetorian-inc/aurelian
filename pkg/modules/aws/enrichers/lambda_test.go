package enrichers_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLambdaClient for testing
type mockLambdaClient struct {
	urlConfig *lambda.GetFunctionUrlConfigOutput
	urlError  error
}

func (m *mockLambdaClient) GetFunctionUrlConfig(ctx context.Context, input *lambda.GetFunctionUrlConfigInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	return m.urlConfig, m.urlError
}

func TestFetchFunctionURLs(t *testing.T) {
	// Mock Lambda client with function URL configured
	mockClient := &mockLambdaClient{
		urlConfig: &lambda.GetFunctionUrlConfigOutput{
			FunctionUrl: aws.String("https://abc123.lambda-url.us-east-1.on.aws/"),
			AuthType:    lambdatypes.FunctionUrlAuthTypeNone,
		},
	}

	resource := &output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		Properties:   make(map[string]any),
	}

	// Create enricher config with mock client
	cfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: aws.Config{}, // Real config not needed with mock
	}

	// Execute enricher (test expects enricher to accept mock client)
	err := enrichers.FetchFunctionURLs(cfg, resource, mockClient)
	require.NoError(t, err)

	// Verify properties added
	assert.Equal(t, "https://abc123.lambda-url.us-east-1.on.aws/", resource.Properties["FunctionUrl"])
	assert.Equal(t, "NONE", resource.Properties["FunctionUrlAuthType"])
}

func TestFetchFunctionURLsNoURL(t *testing.T) {
	// Mock client returns ResourceNotFoundException
	mockClient := &mockLambdaClient{
		urlError: &lambdatypes.ResourceNotFoundException{},
	}

	resource := &output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "no-url-function",
		Properties:   make(map[string]any),
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}

	// Enricher should return nil (not an error - just no URL configured)
	err := enrichers.FetchFunctionURLs(cfg, resource, mockClient)
	assert.NoError(t, err)
	assert.Empty(t, resource.Properties, "No properties should be added when no URL exists")
}
