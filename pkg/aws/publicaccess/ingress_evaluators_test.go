package publicaccess

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CloudFront ---

func TestEvaluateCloudFront_EnabledNoWAF(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{
		ResourceType: "AWS::CloudFront::Distribution",
		ResourceID:   "E123",
		Properties:   map[string]any{"DistributionEnabled": true, "HasWebACL": false},
	}
	result := e.evaluateCloudFront(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Equal(t, []string{"cloudfront:NetworkAccess"}, result.AllowedActions)
	require.Len(t, result.EvaluationReasons, 1)
	assert.Contains(t, result.EvaluationReasons[0], "no WAF web ACL")
}

func TestEvaluateCloudFront_EnabledWithWAF(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{
		ResourceType: "AWS::CloudFront::Distribution",
		ResourceID:   "E123",
		Properties:   map[string]any{"DistributionEnabled": true, "HasWebACL": true},
	}
	result := e.evaluateCloudFront(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.EvaluationReasons[0], "WAF web ACL attached")
}

func TestEvaluateCloudFront_Disabled(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"DistributionEnabled": false}}
	assert.Nil(t, e.evaluateCloudFront(r, aws.Config{}, ""))
}

// --- Global Accelerator ---

func TestEvaluateGlobalAccelerator_Enabled(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"Enabled": true}}
	result := e.evaluateGlobalAccelerator(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Equal(t, []string{"globalaccelerator:NetworkAccess"}, result.AllowedActions)
}

func TestEvaluateGlobalAccelerator_Disabled(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"Enabled": false}}
	assert.Nil(t, e.evaluateGlobalAccelerator(r, aws.Config{}, ""))
}

// --- Elastic Beanstalk ---

func TestEvaluateElasticBeanstalk_WithEndpoint(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointURL": "myenv.us-east-1.elasticbeanstalk.com"}}
	result := e.evaluateElasticBeanstalk(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Contains(t, result.EvaluationReasons[0], "myenv.us-east-1.elasticbeanstalk.com")
}

func TestEvaluateElasticBeanstalk_NoEndpoint(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{}}
	assert.Nil(t, e.evaluateElasticBeanstalk(r, aws.Config{}, ""))
}

// --- Transfer Family ---

func TestEvaluateTransfer_Public(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointType": "PUBLIC"}}
	result := e.evaluateTransfer(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.False(t, result.NeedsManualTriage)
	assert.Equal(t, []string{"transfer:NetworkAccess"}, result.AllowedActions)
}

func TestEvaluateTransfer_VPC(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointType": "VPC"}}
	assert.Nil(t, e.evaluateTransfer(r, aws.Config{}, ""))
}

// --- AppSync ---

func TestEvaluateAppSync_APIKey(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"AuthenticationType": "API_KEY"}}
	result := e.evaluateAppSync(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Contains(t, result.EvaluationReasons[0], "API_KEY")
}

func TestEvaluateAppSync_IAMAuth(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"AuthenticationType": "AWS_IAM"}}
	assert.Nil(t, e.evaluateAppSync(r, aws.Config{}, ""))
}

func TestEvaluateAppSync_CognitoAuth(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"AuthenticationType": "AMAZON_COGNITO_USER_POOLS"}}
	assert.Nil(t, e.evaluateAppSync(r, aws.Config{}, ""))
}

// --- OpenSearch / Elasticsearch ---

func TestEvaluateOpenSearch_FGACDisabled(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"FGACEnabled": false}}
	result := e.evaluateOpenSearch(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.False(t, result.IsPublic, "FGAC-disabled is triage-only, not auto-public")
	assert.True(t, result.NeedsManualTriage)
	assert.Equal(t, []string{"es:ESHttpGet"}, result.AllowedActions)
	assert.Contains(t, result.EvaluationReasons[0], "fine-grained access control disabled")
}

func TestEvaluateOpenSearch_FGACEnabled(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"FGACEnabled": true}}
	assert.Nil(t, e.evaluateOpenSearch(r, aws.Config{}, ""))
}

// --- EKS ---

func TestEvaluateEKS_PublicOpenToInternet(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointPublicAccess": true, "PublicAccessOpenToInternet": true}}
	result := e.evaluateEKS(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic, "public endpoint open to 0.0.0.0/0 is public, not just triage")
	assert.False(t, result.NeedsManualTriage)
	assert.Contains(t, result.EvaluationReasons[0], "0.0.0.0/0")
}

func TestEvaluateEKS_PublicScoped(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointPublicAccess": true, "PublicAccessOpenToInternet": false}}
	result := e.evaluateEKS(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.False(t, result.IsPublic, "public-but-CIDR-scoped endpoint is triage-only")
	assert.True(t, result.NeedsManualTriage)
}

func TestEvaluateEKS_PrivateEndpoint(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"EndpointPublicAccess": false, "PublicAccessOpenToInternet": false}}
	assert.Nil(t, e.evaluateEKS(r, aws.Config{}, ""))
}

// --- API Gateway REST ---

func TestEvaluateAPIGatewayRest_HasUnauthMethods(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"UnauthenticatedMethodCount": 3, "TotalMethodCount": 5}}
	result := e.evaluateAPIGatewayRest(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Equal(t, []string{"execute-api:Invoke"}, result.AllowedActions)
	assert.Contains(t, result.EvaluationReasons[0], "3 method(s)")
}

func TestEvaluateAPIGatewayRest_AllAuthenticated(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"UnauthenticatedMethodCount": 0, "TotalMethodCount": 5}}
	assert.Nil(t, e.evaluateAPIGatewayRest(r, aws.Config{}, ""))
}

func TestEvaluateAPIGatewayRest_MissingProperty(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{}}
	assert.Nil(t, e.evaluateAPIGatewayRest(r, aws.Config{}, ""))
}

// --- API Gateway HTTP/WebSocket ---

func TestEvaluateAPIGatewayV2_HasUnauthRoutes(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"UnauthenticatedRouteCount": 2, "TotalRouteCount": 4}}
	result := e.evaluateAPIGatewayV2(r, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.EvaluationReasons[0], "2 route(s)")
}

func TestEvaluateAPIGatewayV2_AllAuthenticated(t *testing.T) {
	e := newTestEvaluator()
	r := &output.AWSResource{Properties: map[string]any{"UnauthenticatedRouteCount": 0, "TotalRouteCount": 4}}
	assert.Nil(t, e.evaluateAPIGatewayV2(r, aws.Config{}, ""))
}

// --- End-to-end dispatch through evaluateCore (AccessLevel assignment) ---

func TestEvaluateCore_IngressDispatch(t *testing.T) {
	cases := []struct {
		name        string
		resource    *output.AWSResource
		expectLevel output.AccessLevel
	}{
		{
			name: "internet-facing ELBv2 -> NeedsTriage",
			resource: &output.AWSResource{
				ResourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
				ResourceID:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc",
				Properties:   map[string]any{"IsInternetFacing": true},
			},
			expectLevel: output.AccessLevelNeedsTriage,
		},
		{
			name: "public Transfer server -> Public",
			resource: &output.AWSResource{
				ResourceType: "AWS::Transfer::Server",
				ResourceID:   "s-abc",
				Properties:   map[string]any{"EndpointType": "PUBLIC"},
			},
			expectLevel: output.AccessLevelPublic,
		},
		{
			name: "unauthenticated HTTP API -> Public",
			resource: &output.AWSResource{
				ResourceType: "AWS::ApiGatewayV2::Api",
				ResourceID:   "api-abc",
				Properties:   map[string]any{"UnauthenticatedRouteCount": 1},
			},
			expectLevel: output.AccessLevelPublic,
		},
		{
			name: "FGAC-enabled OpenSearch -> Private",
			resource: &output.AWSResource{
				ResourceType: "AWS::OpenSearchService::Domain",
				ResourceID:   "dom-abc",
				Properties:   map[string]any{"FGACEnabled": true},
			},
			expectLevel: output.AccessLevelPrivate,
		},
	}

	e := newTestEvaluator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := collectCore(e, tc.resource)
			require.Len(t, results, 1)
			assert.Equal(t, tc.expectLevel, results[0].AWSResource.AccessLevel)
		})
	}
}
