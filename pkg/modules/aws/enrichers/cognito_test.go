package enrichers_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCognitoClient struct {
	describePoolOutput   *cognitoidentityprovider.DescribeUserPoolOutput
	describePoolError    error
	listClientsOutput    *cognitoidentityprovider.ListUserPoolClientsOutput
	listClientsError     error
	describeClientOutput *cognitoidentityprovider.DescribeUserPoolClientOutput
	describeClientError  error
}

func (m *mockCognitoClient) DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return m.describePoolOutput, m.describePoolError
}

func (m *mockCognitoClient) ListUserPoolClients(ctx context.Context, params *cognitoidentityprovider.ListUserPoolClientsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolClientsOutput, error) {
	return m.listClientsOutput, m.listClientsError
}

func (m *mockCognitoClient) DescribeUserPoolClient(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolClientInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error) {
	return m.describeClientOutput, m.describeClientError
}

func TestEnrichCognitoUserPool_SelfSignupEnabled(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: false,
				},
				Domain: aws.String("my-domain"),
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abcdef",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abcdef"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	assert.True(t, resource.Properties["SelfSignupEnabled"].(bool))
	assert.Equal(t, []string{"my-domain"}, resource.Properties["Domains"])
}

func TestEnrichCognitoUserPool_SelfSignupDisabled(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: true,
				},
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abcdef",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abcdef"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	assert.False(t, resource.Properties["SelfSignupEnabled"].(bool))
}

func TestEnrichCognitoUserPool_NoPoolID(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abcdef",
		Properties:   map[string]any{},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, &mockCognitoClient{})
	require.NoError(t, err)
}

func TestEnrichCognitoUserPool_NotFound(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolError: &cognitotypes.ResourceNotFoundException{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abcdef",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abcdef"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)
}

func TestEnrichCognitoUserPool_WithClients(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: false,
				},
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{
				{ClientId: aws.String("client-1"), ClientName: aws.String("WebApp")},
			},
		},
		describeClientOutput: &cognitoidentityprovider.DescribeUserPoolClientOutput{
			UserPoolClient: &cognitotypes.UserPoolClientType{
				ClientId:          aws.String("client-1"),
				ClientName:        aws.String("WebApp"),
				AllowedOAuthFlows: []cognitotypes.OAuthFlowType{cognitotypes.OAuthFlowTypeCode},
				CallbackURLs:      []string{"https://app.example.com/callback"},
				AllowedOAuthScopes: []string{"openid", "profile"},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abc123"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	clientProps, ok := resource.Properties["ClientProperties"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, clientProps, 1)

	assert.Equal(t, "client-1", clientProps[0]["ClientId"])
	assert.Equal(t, "WebApp", clientProps[0]["ClientName"])
	assert.Equal(t, []string{"code"}, clientProps[0]["AllowedOAuthFlows"])
	assert.Equal(t, []string{"https://app.example.com/callback"}, clientProps[0]["CallbackURLs"])
	assert.Equal(t, []string{"openid", "profile"}, clientProps[0]["AllowedOAuthScopes"])
}

func TestEnrichCognitoUserPool_NilAdminConfig(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: nil, // nil means default: self-signup allowed
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abcdef",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abcdef"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	assert.True(t, resource.Properties["SelfSignupEnabled"].(bool),
		"self-signup should default to enabled when AdminCreateUserConfig is nil")
}

func TestEnrichCognitoUserPool_BothDomains(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: false,
				},
				Domain:       aws.String("my-domain"),
				CustomDomain: aws.String("auth.example.com"),
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abc123"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	domains, ok := resource.Properties["Domains"].([]string)
	require.True(t, ok)
	assert.Len(t, domains, 2)
	assert.Contains(t, domains, "my-domain")
	assert.Contains(t, domains, "auth.example.com")
}
