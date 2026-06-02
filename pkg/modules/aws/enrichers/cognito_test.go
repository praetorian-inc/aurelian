package enrichers_test

import (
	"context"
	"errors"
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
	listClientsOutputs   []*cognitoidentityprovider.ListUserPoolClientsOutput
	listClientsError     error
	listClientsInputs    []*cognitoidentityprovider.ListUserPoolClientsInput
	describeClientOutput *cognitoidentityprovider.DescribeUserPoolClientOutput
	describeClientError  error
	describeClientFunc   func(clientID string) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error)
	listGroupsOutput     *cognitoidentityprovider.ListGroupsOutput
	listGroupsOutputs    []*cognitoidentityprovider.ListGroupsOutput
	listGroupsError      error
	listGroupsInputs     []*cognitoidentityprovider.ListGroupsInput
}

func (m *mockCognitoClient) DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return m.describePoolOutput, m.describePoolError
}

func (m *mockCognitoClient) ListUserPoolClients(ctx context.Context, params *cognitoidentityprovider.ListUserPoolClientsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolClientsOutput, error) {
	m.listClientsInputs = append(m.listClientsInputs, params)
	if m.listClientsError != nil {
		return nil, m.listClientsError
	}
	if len(m.listClientsOutputs) > 0 {
		idx := len(m.listClientsInputs) - 1
		if idx >= len(m.listClientsOutputs) {
			return nil, nil
		}
		return m.listClientsOutputs[idx], nil
	}
	return m.listClientsOutput, nil
}

func (m *mockCognitoClient) DescribeUserPoolClient(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolClientInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error) {
	if m.describeClientFunc != nil {
		return m.describeClientFunc(stringPtrVal(params.ClientId))
	}
	return m.describeClientOutput, m.describeClientError
}

func stringPtrVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (m *mockCognitoClient) ListGroups(ctx context.Context, params *cognitoidentityprovider.ListGroupsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListGroupsOutput, error) {
	m.listGroupsInputs = append(m.listGroupsInputs, params)
	if m.listGroupsError != nil {
		return nil, m.listGroupsError
	}
	if len(m.listGroupsOutputs) > 0 {
		idx := len(m.listGroupsInputs) - 1
		if idx >= len(m.listGroupsOutputs) {
			return nil, nil
		}
		return m.listGroupsOutputs[idx], nil
	}
	return m.listGroupsOutput, m.listGroupsError
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
				ClientId:           aws.String("client-1"),
				ClientName:         aws.String("WebApp"),
				AllowedOAuthFlows:  []cognitotypes.OAuthFlowType{cognitotypes.OAuthFlowTypeCode},
				CallbackURLs:       []string{"https://app.example.com/callback"},
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

func TestEnrichCognitoUserPool_WithGroupRoles(t *testing.T) {
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
		listGroupsOutput: &cognitoidentityprovider.ListGroupsOutput{
			Groups: []cognitotypes.GroupType{
				{GroupName: aws.String("admins"), RoleArn: aws.String("arn:aws:iam::123456789012:role/AdminRole")},
				{GroupName: aws.String("users"), RoleArn: aws.String("arn:aws:iam::123456789012:role/UserRole")},
				{GroupName: aws.String("no-role")},
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

	roles, ok := resource.Properties["Roles"].([]string)
	require.True(t, ok)
	assert.Len(t, roles, 2)
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/AdminRole")
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/UserRole")
}

func TestEnrichCognitoUserPool_NoGroupRoles(t *testing.T) {
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
		listGroupsOutput: &cognitoidentityprovider.ListGroupsOutput{
			Groups: []cognitotypes.GroupType{
				{GroupName: aws.String("no-role")},
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

	_, exists := resource.Properties["Roles"]
	assert.False(t, exists, "Roles should not be set when no groups have roles")
}

func TestEnrichCognitoUserPool_GroupRolesPagination(t *testing.T) {
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
		listGroupsOutputs: []*cognitoidentityprovider.ListGroupsOutput{
			{
				Groups: []cognitotypes.GroupType{
					{GroupName: aws.String("no-role")},
				},
				NextToken: aws.String("page-2"),
			},
			{
				Groups: []cognitotypes.GroupType{
					{GroupName: aws.String("admins"), RoleArn: aws.String("arn:aws:iam::123456789012:role/AdminRole")},
				},
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

	roles, ok := resource.Properties["Roles"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/AdminRole"}, roles)

	require.Len(t, mockClient.listGroupsInputs, 2)
	assert.Nil(t, mockClient.listGroupsInputs[0].NextToken)
	require.NotNil(t, mockClient.listGroupsInputs[1].NextToken)
	assert.Equal(t, "page-2", *mockClient.listGroupsInputs[1].NextToken)
}

func TestEnrichCognitoUserPool_ListGroupsErrorContinues(t *testing.T) {
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
		listGroupsError: errors.New("access denied"),
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties:   map[string]any{"UserPoolId": "us-east-1_abc123"},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichCognitoUserPool(cfg, resource, mockClient)
	require.NoError(t, err)

	_, exists := resource.Properties["Roles"]
	assert.False(t, exists, "Roles should not be set when ListGroups fails")
	require.Len(t, mockClient.listGroupsInputs, 1)
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

func TestEnrichCognitoUserPool_ClientsPagination(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: true,
				},
			},
		},
		listClientsOutputs: []*cognitoidentityprovider.ListUserPoolClientsOutput{
			{
				UserPoolClients: []cognitotypes.UserPoolClientDescription{
					{ClientId: aws.String("client-1"), ClientName: aws.String("WebApp")},
				},
				NextToken: aws.String("page-2"),
			},
			{
				UserPoolClients: []cognitotypes.UserPoolClientDescription{
					{ClientId: aws.String("client-2"), ClientName: aws.String("MobileApp")},
				},
			},
		},
		describeClientFunc: func(clientID string) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error) {
			return &cognitoidentityprovider.DescribeUserPoolClientOutput{
				UserPoolClient: &cognitotypes.UserPoolClientType{
					ClientId:   aws.String(clientID),
					ClientName: aws.String(clientID + "-name"),
				},
			}, nil
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
	require.Len(t, clientProps, 2)
	assert.Equal(t, "client-1", clientProps[0]["ClientId"])
	assert.Equal(t, "client-2", clientProps[1]["ClientId"])

	require.Len(t, mockClient.listClientsInputs, 2)
	assert.Nil(t, mockClient.listClientsInputs[0].NextToken)
	require.NotNil(t, mockClient.listClientsInputs[1].NextToken)
	assert.Equal(t, "page-2", *mockClient.listClientsInputs[1].NextToken)
}

func TestEnrichCognitoUserPool_PartialClientDescribeFailure(t *testing.T) {
	mockClient := &mockCognitoClient{
		describePoolOutput: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &cognitotypes.UserPoolType{
				AdminCreateUserConfig: &cognitotypes.AdminCreateUserConfigType{
					AllowAdminCreateUserOnly: true,
				},
			},
		},
		listClientsOutput: &cognitoidentityprovider.ListUserPoolClientsOutput{
			UserPoolClients: []cognitotypes.UserPoolClientDescription{
				{ClientId: aws.String("client-ok"), ClientName: aws.String("Good")},
				{ClientId: aws.String("client-bad"), ClientName: aws.String("Bad")},
			},
		},
		describeClientFunc: func(clientID string) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error) {
			if clientID == "client-bad" {
				return nil, errors.New("access denied")
			}
			return &cognitoidentityprovider.DescribeUserPoolClientOutput{
				UserPoolClient: &cognitotypes.UserPoolClientType{
					ClientId:   aws.String(clientID),
					ClientName: aws.String("Good"),
				},
			}, nil
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
	assert.Equal(t, "client-ok", clientProps[0]["ClientId"])
}
