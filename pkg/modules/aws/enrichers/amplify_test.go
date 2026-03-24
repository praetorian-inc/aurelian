package enrichers_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	amplifytypes "github.com/aws/aws-sdk-go-v2/service/amplify/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAmplifyClient struct {
	branches *amplify.ListBranchesOutput
	err      error
}

func (m *mockAmplifyClient) ListBranches(_ context.Context, _ *amplify.ListBranchesInput, _ ...func(*amplify.Options)) (*amplify.ListBranchesOutput, error) {
	return m.branches, m.err
}

func TestEnrichAmplifyApp_WithBranches(t *testing.T) {
	client := &mockAmplifyClient{
		branches: &amplify.ListBranchesOutput{
			Branches: []amplifytypes.Branch{
				{DisplayName: aws.String("main")},
				{DisplayName: aws.String("develop")},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   "d1234567890",
		Properties: map[string]any{
			"AppId":         "d1234567890",
			"DefaultDomain": "d1234567890.amplifyapp.com",
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichAmplifyApp(cfg, resource, client)
	require.NoError(t, err)

	assert.Equal(t, []string{"main", "develop"}, resource.Properties["BranchNames"])
	assert.Equal(t, 2, resource.Properties["BranchCount"])
	assert.Equal(t, []string{
		"https://main.d1234567890.amplifyapp.com",
		"https://develop.d1234567890.amplifyapp.com",
	}, resource.URLs)
}

func TestEnrichAmplifyApp_NoBranches(t *testing.T) {
	client := &mockAmplifyClient{
		branches: &amplify.ListBranchesOutput{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   "d1234567890",
		Properties: map[string]any{
			"AppId":         "d1234567890",
			"DefaultDomain": "d1234567890.amplifyapp.com",
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichAmplifyApp(cfg, resource, client)
	require.NoError(t, err)

	assert.Nil(t, resource.Properties["BranchNames"])
	assert.Nil(t, resource.Properties["BranchCount"])
	assert.Empty(t, resource.URLs)
}

func TestEnrichAmplifyApp_MissingAppID(t *testing.T) {
	client := &mockAmplifyClient{}

	resource := &output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   "d1234567890",
		Properties:   map[string]any{"DefaultDomain": "d1234567890.amplifyapp.com"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichAmplifyApp(cfg, resource, client)
	require.NoError(t, err)
	assert.Empty(t, resource.URLs, "should skip when AppId is missing")
}

func TestEnrichAmplifyApp_MissingDefaultDomain(t *testing.T) {
	client := &mockAmplifyClient{}

	resource := &output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   "d1234567890",
		Properties:   map[string]any{"AppId": "d1234567890"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichAmplifyApp(cfg, resource, client)
	require.NoError(t, err)
	assert.Empty(t, resource.URLs, "should skip when DefaultDomain is missing")
}

func TestEnrichAmplifyApp_APIError(t *testing.T) {
	client := &mockAmplifyClient{
		err: fmt.Errorf("access denied"),
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   "d1234567890",
		Properties: map[string]any{
			"AppId":         "d1234567890",
			"DefaultDomain": "d1234567890.amplifyapp.com",
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichAmplifyApp(cfg, resource, client)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list amplify branches")
}
