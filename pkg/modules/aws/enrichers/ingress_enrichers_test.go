package enrichers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool     { return &b }

// --- Flatten enrichers (no AWS calls) ---

func TestEnrichELBv2_InternetFacing(t *testing.T) {
	r := &output.AWSResource{Properties: map[string]any{"Scheme": "internet-facing"}}
	require.NoError(t, enrichers.EnrichELBv2LoadBalancer(plugin.EnricherConfig{}, r))
	assert.Equal(t, true, r.Properties["IsInternetFacing"])
}

func TestEnrichELBv2_Internal(t *testing.T) {
	r := &output.AWSResource{Properties: map[string]any{"Scheme": "internal"}}
	require.NoError(t, enrichers.EnrichELBv2LoadBalancer(plugin.EnricherConfig{}, r))
	assert.Equal(t, false, r.Properties["IsInternetFacing"])
}

func TestEnrichELBv2_MissingScheme(t *testing.T) {
	r := &output.AWSResource{Properties: map[string]any{}}
	require.NoError(t, enrichers.EnrichELBv2LoadBalancer(plugin.EnricherConfig{}, r))
	assert.Equal(t, false, r.Properties["IsInternetFacing"])
}

func TestEnrichAppRunner_PublicIngress(t *testing.T) {
	r := &output.AWSResource{Properties: map[string]any{
		"NetworkConfiguration": map[string]any{
			"IngressConfiguration": map[string]any{"IsPubliclyAccessible": true},
		},
	}}
	require.NoError(t, enrichers.EnrichAppRunnerService(plugin.EnricherConfig{}, r))
	assert.Equal(t, true, r.Properties["IsPubliclyAccessible"])
}

func TestEnrichAppRunner_PrivateAndMalformed(t *testing.T) {
	// Private ingress.
	r := &output.AWSResource{Properties: map[string]any{
		"NetworkConfiguration": map[string]any{
			"IngressConfiguration": map[string]any{"IsPubliclyAccessible": false},
		},
	}}
	require.NoError(t, enrichers.EnrichAppRunnerService(plugin.EnricherConfig{}, r))
	assert.Equal(t, false, r.Properties["IsPubliclyAccessible"])

	// Missing nested structure must not panic and defaults to false.
	r2 := &output.AWSResource{Properties: map[string]any{"NetworkConfiguration": "not-a-map"}}
	require.NoError(t, enrichers.EnrichAppRunnerService(plugin.EnricherConfig{}, r2))
	assert.Equal(t, false, r2.Properties["IsPubliclyAccessible"])
}

func TestEnrichCloudFront(t *testing.T) {
	cases := []struct {
		name        string
		config      any
		wantEnabled bool
		wantWAF     bool
	}{
		{"enabled with WAF", map[string]any{"Enabled": true, "WebACLId": "arn:aws:wafv2:...:webacl/x"}, true, true},
		{"enabled no WAF", map[string]any{"Enabled": true, "WebACLId": ""}, true, false},
		{"disabled", map[string]any{"Enabled": false}, false, false},
		{"malformed config", "not-a-map", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &output.AWSResource{Properties: map[string]any{"DistributionConfig": tc.config}}
			require.NoError(t, enrichers.EnrichCloudFrontDistribution(plugin.EnricherConfig{}, r))
			assert.Equal(t, tc.wantEnabled, r.Properties["DistributionEnabled"])
			assert.Equal(t, tc.wantWAF, r.Properties["HasWebACL"])
		})
	}
}

func TestEnrichOpenSearch(t *testing.T) {
	cases := []struct {
		name    string
		options any
		wantFGAC bool
	}{
		{"FGAC on", map[string]any{"Enabled": true}, true},
		{"FGAC off", map[string]any{"Enabled": false}, false},
		{"missing options", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			props := map[string]any{}
			if tc.options != nil {
				props["AdvancedSecurityOptions"] = tc.options
			}
			r := &output.AWSResource{Properties: props}
			require.NoError(t, enrichers.EnrichOpenSearchDomain(plugin.EnricherConfig{}, r))
			assert.Equal(t, tc.wantFGAC, r.Properties["FGACEnabled"])
		})
	}
}

func TestEnrichOpenSearch_WildcardPolicy(t *testing.T) {
	allow := func(principal string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"es:ESHttpGet"}]}`
	}
	cases := []struct {
		name   string
		policy string
		want   bool
	}{
		{"string wildcard", allow(`"*"`), true},
		{"AWS wildcard string", allow(`{"AWS":"*"}`), true},
		{"AWS wildcard list", allow(`{"AWS":["arn:aws:iam::111:root","*"]}`), true},
		{"restrictive principal", allow(`{"AWS":"arn:aws:iam::111:root"}`), false},
		{"single statement object", `{"Statement":{"Effect":"Allow","Principal":"*"}}`, true},
		{"deny wildcard not counted", `{"Statement":[{"Effect":"Deny","Principal":"*"}]}`, false},
		{"malformed", `{not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &output.AWSResource{Properties: map[string]any{
				"AdvancedSecurityOptions": map[string]any{"Enabled": false},
				"AccessPolicies":          tc.policy,
			}}
			require.NoError(t, enrichers.EnrichOpenSearchDomain(plugin.EnricherConfig{}, r))
			assert.Equal(t, false, r.Properties["FGACEnabled"])
			assert.Equal(t, tc.want, r.Properties["HasWildcardAccessPolicy"], tc.name)
		})
	}
}

func TestEnrichEKS(t *testing.T) {
	cases := []struct {
		name           string
		vpcConfig      any
		wantPublic     bool
		wantOpenToNet  bool
	}{
		{"public open to internet", map[string]any{"EndpointPublicAccess": true, "PublicAccessCidrs": []any{"0.0.0.0/0"}}, true, true},
		{"public scoped", map[string]any{"EndpointPublicAccess": true, "PublicAccessCidrs": []any{"203.0.113.0/24"}}, true, false},
		{"private", map[string]any{"EndpointPublicAccess": false}, false, false},
		{"malformed", "not-a-map", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &output.AWSResource{Properties: map[string]any{"ResourcesVpcConfig": tc.vpcConfig}}
			require.NoError(t, enrichers.EnrichEKSCluster(plugin.EnricherConfig{}, r))
			assert.Equal(t, tc.wantPublic, r.Properties["EndpointPublicAccess"])
			assert.Equal(t, tc.wantOpenToNet, r.Properties["PublicAccessOpenToInternet"])
		})
	}
}

// --- Beanstalk (mock client) ---

type mockBeanstalkClient struct {
	envType   string
	elbScheme string
}

func (m *mockBeanstalkClient) DescribeConfigurationSettings(_ context.Context, _ *elasticbeanstalk.DescribeConfigurationSettingsInput, _ ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error) {
	var opts []ebtypes.ConfigurationOptionSetting
	if m.envType != "" {
		opts = append(opts, ebtypes.ConfigurationOptionSetting{
			Namespace: strPtr("aws:elasticbeanstalk:environment"), OptionName: strPtr("EnvironmentType"), Value: strPtr(m.envType),
		})
	}
	if m.elbScheme != "" {
		opts = append(opts, ebtypes.ConfigurationOptionSetting{
			Namespace: strPtr("aws:ec2:vpc"), OptionName: strPtr("ELBScheme"), Value: strPtr(m.elbScheme),
		})
	}
	return &elasticbeanstalk.DescribeConfigurationSettingsOutput{
		ConfigurationSettings: []ebtypes.ConfigurationSettingsDescription{{OptionSettings: opts}},
	}, nil
}

func TestEnrichBeanstalk_InternalVsPublic(t *testing.T) {
	cases := []struct {
		name           string
		envType        string
		elbScheme      string
		wantInternalLB bool
	}{
		{"load-balanced internal", "LoadBalanced", "internal", true},
		{"load-balanced public", "LoadBalanced", "public", false},
		{"single instance", "SingleInstance", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &output.AWSResource{Properties: map[string]any{"ApplicationName": "app", "EnvironmentName": "env"}}
			mock := &mockBeanstalkClient{envType: tc.envType, elbScheme: tc.elbScheme}
			require.NoError(t, enrichers.EnrichBeanstalkEnvironment(plugin.EnricherConfig{Context: context.Background()}, r, mock))
			assert.Equal(t, tc.wantInternalLB, r.Properties["IsInternalLB"], tc.name)
		})
	}
}

func TestEnrichBeanstalk_MissingAppEnv(t *testing.T) {
	r := &output.AWSResource{Properties: map[string]any{}}
	mock := &mockBeanstalkClient{envType: "LoadBalanced", elbScheme: "internal"}
	require.NoError(t, enrichers.EnrichBeanstalkEnvironment(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	_, set := r.Properties["IsInternalLB"]
	assert.False(t, set, "no config lookup without app/env")
}

// --- API Gateway REST (mock client) ---

type mockAPIGatewayClient struct {
	pages []*apigateway.GetResourcesOutput
	err   error
	calls int
}

func (m *mockAPIGatewayClient) GetResources(_ context.Context, _ *apigateway.GetResourcesInput, _ ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := m.pages[m.calls]
	m.calls++
	return out, nil
}

func TestEnrichAPIGatewayRest_MixedMethods(t *testing.T) {
	// 2 unauthenticated (NONE, no key), 1 authenticated (AWS_IAM), 1 NONE-but-key-required.
	mock := &mockAPIGatewayClient{pages: []*apigateway.GetResourcesOutput{{
		Items: []apigwtypes.Resource{{
			ResourceMethods: map[string]apigwtypes.Method{
				"GET":  {AuthorizationType: strPtr("NONE"), ApiKeyRequired: boolPtr(false)},
				"POST": {AuthorizationType: strPtr("NONE")},
				"PUT":  {AuthorizationType: strPtr("AWS_IAM")},
				"DELETE": {AuthorizationType: strPtr("NONE"), ApiKeyRequired: boolPtr(true)},
			},
		}},
		Position: nil,
	}}}
	r := &output.AWSResource{Properties: map[string]any{"RestApiId": "abc123"}}
	require.NoError(t, enrichers.EnrichAPIGatewayRestAPI(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 4, r.Properties["TotalMethodCount"])
	assert.Equal(t, 2, r.Properties["UnauthenticatedMethodCount"])
}

func TestEnrichAPIGatewayRest_AllAuthenticated(t *testing.T) {
	mock := &mockAPIGatewayClient{pages: []*apigateway.GetResourcesOutput{{
		Items: []apigwtypes.Resource{{
			ResourceMethods: map[string]apigwtypes.Method{
				"GET":  {AuthorizationType: strPtr("AWS_IAM")},
				"POST": {AuthorizationType: strPtr("COGNITO_USER_POOLS")},
			},
		}},
	}}}
	r := &output.AWSResource{Properties: map[string]any{"RestApiId": "abc123"}}
	require.NoError(t, enrichers.EnrichAPIGatewayRestAPI(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 2, r.Properties["TotalMethodCount"])
	assert.Equal(t, 0, r.Properties["UnauthenticatedMethodCount"])
}

func TestEnrichAPIGatewayRest_Paginated(t *testing.T) {
	mock := &mockAPIGatewayClient{pages: []*apigateway.GetResourcesOutput{
		{Items: []apigwtypes.Resource{{ResourceMethods: map[string]apigwtypes.Method{"GET": {AuthorizationType: strPtr("NONE")}}}}, Position: strPtr("p2")},
		{Items: []apigwtypes.Resource{{ResourceMethods: map[string]apigwtypes.Method{"POST": {AuthorizationType: strPtr("NONE")}}}}, Position: nil},
	}}
	r := &output.AWSResource{Properties: map[string]any{"RestApiId": "abc123"}}
	require.NoError(t, enrichers.EnrichAPIGatewayRestAPI(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 2, mock.calls, "should follow pagination across both pages")
	assert.Equal(t, 2, r.Properties["UnauthenticatedMethodCount"])
}

func TestEnrichAPIGatewayRest_NoRestApiId(t *testing.T) {
	mock := &mockAPIGatewayClient{}
	r := &output.AWSResource{Properties: map[string]any{}}
	require.NoError(t, enrichers.EnrichAPIGatewayRestAPI(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 0, mock.calls, "no API call without a RestApiId")
	_, set := r.Properties["UnauthenticatedMethodCount"]
	assert.False(t, set)
}

func TestEnrichAPIGatewayRest_Error(t *testing.T) {
	mock := &mockAPIGatewayClient{err: errors.New("access denied")}
	r := &output.AWSResource{Properties: map[string]any{"RestApiId": "abc123"}}
	err := enrichers.EnrichAPIGatewayRestAPI(plugin.EnricherConfig{Context: context.Background()}, r, mock)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- API Gateway HTTP/WebSocket (mock client) ---

type mockAPIGatewayV2Client struct {
	pages []*apigatewayv2.GetRoutesOutput
	calls int
}

func (m *mockAPIGatewayV2Client) GetRoutes(_ context.Context, _ *apigatewayv2.GetRoutesInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	out := m.pages[m.calls]
	m.calls++
	return out, nil
}

func TestEnrichAPIGatewayV2_MixedRoutes(t *testing.T) {
	// 2 NONE (unauthenticated), 1 JWT, 1 AWS_IAM.
	mock := &mockAPIGatewayV2Client{pages: []*apigatewayv2.GetRoutesOutput{{
		Items: []apiv2types.Route{
			{RouteKey: strPtr("GET /public"), AuthorizationType: apiv2types.AuthorizationTypeNone},
			{RouteKey: strPtr("$default"), AuthorizationType: apiv2types.AuthorizationTypeNone},
			{RouteKey: strPtr("GET /jwt"), AuthorizationType: apiv2types.AuthorizationTypeJwt},
			{RouteKey: strPtr("GET /iam"), AuthorizationType: apiv2types.AuthorizationTypeAwsIam},
		},
	}}}
	r := &output.AWSResource{Properties: map[string]any{"ApiId": "api123"}}
	require.NoError(t, enrichers.EnrichAPIGatewayV2(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 4, r.Properties["TotalRouteCount"])
	assert.Equal(t, 2, r.Properties["UnauthenticatedRouteCount"])
}

func TestEnrichAPIGatewayV2_AllAuthenticated(t *testing.T) {
	mock := &mockAPIGatewayV2Client{pages: []*apigatewayv2.GetRoutesOutput{{
		Items: []apiv2types.Route{
			{RouteKey: strPtr("GET /a"), AuthorizationType: apiv2types.AuthorizationTypeJwt},
		},
	}}}
	r := &output.AWSResource{Properties: map[string]any{"ApiId": "api123"}}
	require.NoError(t, enrichers.EnrichAPIGatewayV2(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 0, r.Properties["UnauthenticatedRouteCount"])
}

func TestEnrichAPIGatewayV2_NoApiId(t *testing.T) {
	mock := &mockAPIGatewayV2Client{}
	r := &output.AWSResource{Properties: map[string]any{}}
	require.NoError(t, enrichers.EnrichAPIGatewayV2(plugin.EnricherConfig{Context: context.Background()}, r, mock))
	assert.Equal(t, 0, mock.calls, "no API call without an ApiId")
}
