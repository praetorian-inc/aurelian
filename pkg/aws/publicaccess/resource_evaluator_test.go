package publicaccess

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEvaluator() *ResourceEvaluator {
	return &ResourceEvaluator{}
}

func TestSupportedResourceTypes(t *testing.T) {
	types := SupportedResourceTypes()
	assert.Len(t, types, 10)

	e := newTestEvaluator()
	registry := e.evaluators()
	for _, rt := range types {
		_, ok := registry[rt]
		assert.True(t, ok, "supported type %q should have an evaluator", rt)
	}
}

func TestEvaluateEC2_WithPublicIP(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties:   map[string]any{"PublicIpAddress": "54.123.45.67"},
	}

	result := e.evaluateEC2(resource, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Contains(t, result.AllowedActions, "ec2:NetworkAccess")
}

func TestEvaluateEC2_WithoutPublicIP(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties:   map[string]any{},
	}

	result := e.evaluateEC2(resource, aws.Config{}, "")
	assert.Nil(t, result)
}

func TestEvaluateRDS_Public(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties:   map[string]any{"IsPubliclyAccessible": true},
	}

	result := e.evaluateRDS(resource, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.False(t, result.NeedsManualTriage)
}

func TestEvaluateRDS_NotPublic(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties:   map[string]any{"IsPubliclyAccessible": false},
	}

	result := e.evaluateRDS(resource, aws.Config{}, "")
	assert.Nil(t, result)
}

func TestEvaluateCognito_SelfSignup(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties:   map[string]any{"SelfSignupEnabled": true},
	}

	result := e.evaluateCognito(resource, aws.Config{}, "")
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
}

func TestEvaluateCognito_NoSelfSignup(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties:   map[string]any{"SelfSignupEnabled": false},
	}

	result := e.evaluateCognito(resource, aws.Config{}, "")
	assert.Nil(t, result)
}

// --- Lambda evaluateLambdaAccess integration tests ---
//
// These tests exercise every combination of resource-policy outcome and
// FunctionUrl AuthType to verify that both checks run independently and
// their results are merged correctly.

const (
	testAccountID    = "123456789012"
	testLambdaARN    = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
	testFunctionName = "my-function"
)

// permissiveLambdaPolicy returns a resource policy that allows Principal "*"
// to invoke the function (public access).
func permissiveLambdaPolicy() *types.Policy {
	policy, err := types.NewPolicyFromJSON([]byte(fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "lambda:InvokeFunction",
			"Resource": "%s"
		}]
	}`, testLambdaARN)))
	if err != nil {
		panic(err)
	}
	return policy
}

// restrictiveLambdaPolicy returns a resource policy that only allows the
// owning account to invoke the function (not public).
func restrictiveLambdaPolicy() *types.Policy {
	policy, err := types.NewPolicyFromJSON([]byte(fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::%s:root"},
			"Action": "lambda:InvokeFunction",
			"Resource": "%s"
		}]
	}`, testAccountID, testLambdaARN)))
	if err != nil {
		panic(err)
	}
	return policy
}

func lambdaResource(props map[string]any) *output.AWSResource {
	if props == nil {
		props = make(map[string]any)
	}
	props["FunctionName"] = testFunctionName
	return &output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   testFunctionName,
		ARN:          testLambdaARN,
		Region:       "us-east-1",
		Properties:   props,
	}
}

// Test 1: Permissive policy + AuthType=NONE → both findings merged.
// This is the scenario that was broken before the fix: the permissive policy
// caused an early return, so the FunctionUrl finding was lost.
func TestEvaluateLambdaAccess_PermissivePolicy_AuthTypeNone(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(map[string]any{"FunctionUrlAuthType": "NONE"})
	policy := permissiveLambdaPolicy()

	result := e.evaluateLambdaAccess(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunction",
		"should include the policy-based finding")
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunctionUrl",
		"should include the FunctionUrl finding")

	// Verify both evaluation reasons are present.
	hasPolicy := false
	hasURL := false
	for _, reason := range result.EvaluationReasons {
		if reason == "Lambda function URL has AuthType NONE (unauthenticated access)" {
			hasURL = true
		}
		if len(reason) > 0 && reason != "Lambda function URL has AuthType NONE (unauthenticated access)" {
			hasPolicy = true
		}
	}
	assert.True(t, hasPolicy, "should have policy evaluation reason")
	assert.True(t, hasURL, "should have FunctionUrl evaluation reason")
}

// Test 2: Permissive policy + AuthType=AWS_IAM → only policy finding.
func TestEvaluateLambdaAccess_PermissivePolicy_AuthTypeIAM(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(map[string]any{"FunctionUrlAuthType": "AWS_IAM"})
	policy := permissiveLambdaPolicy()

	result := e.evaluateLambdaAccess(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunction")
	assert.NotContains(t, result.AllowedActions, "lambda:InvokeFunctionUrl",
		"AuthType=AWS_IAM should not trigger FunctionUrl finding")
}

// Test 3: Permissive policy + no FunctionUrl → only policy finding.
func TestEvaluateLambdaAccess_PermissivePolicy_NoFunctionUrl(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(nil) // no FunctionUrlAuthType
	policy := permissiveLambdaPolicy()

	result := e.evaluateLambdaAccess(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunction")
	assert.NotContains(t, result.AllowedActions, "lambda:InvokeFunctionUrl")
}

// Test 4: Restrictive policy + AuthType=NONE → only FunctionUrl finding.
func TestEvaluateLambdaAccess_RestrictivePolicy_AuthTypeNone(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(map[string]any{"FunctionUrlAuthType": "NONE"})
	policy := restrictiveLambdaPolicy()

	result := e.evaluateLambdaAccess(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunctionUrl")
	assert.NotContains(t, result.AllowedActions, "lambda:InvokeFunction",
		"restrictive policy should not flag lambda:InvokeFunction")
}

// Test 5: Restrictive policy + no FunctionUrl → not public.
func TestEvaluateLambdaAccess_RestrictivePolicy_NoFunctionUrl(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(nil)
	policy := restrictiveLambdaPolicy()

	result := e.evaluateLambdaAccess(resource, policy, nil, testAccountID)

	if result != nil {
		assert.False(t, result.IsPublic, "restrictive policy with no FunctionUrl should not be public")
	}
}

// Test 6: Nil policy + AuthType=NONE → only FunctionUrl finding.
func TestEvaluateLambdaAccess_NilPolicy_AuthTypeNone(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(map[string]any{"FunctionUrlAuthType": "NONE"})

	result := e.evaluateLambdaAccess(resource, nil, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunctionUrl")
	assert.Len(t, result.AllowedActions, 1, "should only have FunctionUrl finding")
}

// Test 7: Nil policy + no FunctionUrl → not public.
func TestEvaluateLambdaAccess_NilPolicy_NoFunctionUrl(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(nil)

	result := e.evaluateLambdaAccess(resource, nil, nil, testAccountID)

	assert.Nil(t, result, "nil policy with no FunctionUrl should return nil")
}

// Test 8: Policy fetch error + AuthType=NONE → still catches FunctionUrl.
func TestEvaluateLambdaAccess_FetchError_AuthTypeNone(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(map[string]any{"FunctionUrlAuthType": "NONE"})

	result := e.evaluateLambdaAccess(resource, nil, fmt.Errorf("access denied"), testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "lambda:InvokeFunctionUrl",
		"FunctionUrl finding should still be reported despite policy fetch error")
}

// Test 9: Policy fetch error + no FunctionUrl → not public (error is logged).
func TestEvaluateLambdaAccess_FetchError_NoFunctionUrl(t *testing.T) {
	e := newTestEvaluator()
	resource := lambdaResource(nil)

	result := e.evaluateLambdaAccess(resource, nil, fmt.Errorf("access denied"), testAccountID)

	assert.Nil(t, result, "policy fetch error with no FunctionUrl should return nil")
}

// --- evaluateCore pipeline flow tests ---
//
// These tests exercise the core evaluation pipeline: evaluator lookup,
// result filtering, PublicAccessResult attachment, and downstream sending.
// Property-based evaluators (EC2, RDS, Cognito) are used because they
// don't require AWS API calls.

// collectCore runs evaluateCore and collects the pipeline output.
func collectCore(e *ResourceEvaluator, resource *output.AWSResource) []PublicAccessResult {
	out := pipeline.New[PublicAccessResult]()
	go func() {
		defer out.Close()
		e.evaluateCore(resource, aws.Config{}, testAccountID, out)
	}()
	results, _ := out.Collect()
	return results
}

func TestEvaluateCore_PublicResource_SentDownstream(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-abc123",
		Region:       "us-east-1",
		Properties:   map[string]any{"PublicIpAddress": "54.1.2.3"},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1, "public resource should be sent downstream")
	assert.Equal(t, "i-abc123", results[0].AWSResource.ResourceID)
	assert.Equal(t, output.AccessLevelNeedsTriage, results[0].AWSResource.AccessLevel)
	assert.True(t, results[0].IsPublic)
	assert.Contains(t, results[0].AllowedActions, "ec2:NetworkAccess")
}

func TestEvaluateCore_NonPublicResource_Filtered(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-private",
		Region:       "us-east-1",
		Properties:   map[string]any{},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1, "supported non-public resource should be sent downstream as private")
	assert.Equal(t, output.AccessLevelPrivate, results[0].AWSResource.AccessLevel)
	assert.False(t, results[0].IsPublic)
}

func TestEvaluateCore_NeedsManualTriage_SentDownstream(t *testing.T) {
	e := newTestEvaluator()
	// EC2 with public IP produces NeedsManualTriage=true
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-triage",
		Region:       "us-east-1",
		Properties:   map[string]any{"PublicIp": "3.4.5.6"},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.True(t, results[0].NeedsManualTriage, "triage resource should be sent downstream")
	assert.Equal(t, output.AccessLevelNeedsTriage, results[0].AWSResource.AccessLevel)
}

func TestEvaluateCore_UnsupportedType_Skipped(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::DynamoDB::Table",
		ResourceID:   "my-table",
		Region:       "us-east-1",
		Properties:   map[string]any{},
	}

	results := collectCore(e, resource)

	assert.Empty(t, results, "unsupported resource type should be silently skipped")
}

func TestEvaluateCore_NilProperties_Initialized(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-nilprops",
		Region:       "us-east-1",
		Properties:   nil,
	}

	_ = collectCore(e, resource)

	assert.NotNil(t, resource.Properties, "nil Properties should be initialized")
}

func TestEvaluateCore_RDS_Public(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Region:       "us-east-1",
		Properties:   map[string]any{"IsPubliclyAccessible": true},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.True(t, results[0].IsPublic)
	assert.Equal(t, output.AccessLevelPublic, results[0].AWSResource.AccessLevel)
}

func TestEvaluateCore_RDS_Private(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb-private",
		Region:       "us-east-1",
		Properties:   map[string]any{"IsPubliclyAccessible": false},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.Equal(t, output.AccessLevelPrivate, results[0].AWSResource.AccessLevel)
	assert.False(t, results[0].IsPublic)
}

func TestEvaluateCore_Redshift_Public(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::Redshift::Cluster",
		ResourceID:   "my-cluster-public",
		Region:       "us-east-1",
		Properties:   map[string]any{"IsPubliclyAccessible": true},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.Equal(t, output.AccessLevelPublic, results[0].AWSResource.AccessLevel)
	assert.True(t, results[0].IsPublic)
	assert.Contains(t, results[0].EvaluationReasons[0], "Redshift cluster is publicly accessible")
}

func TestEvaluateCore_Redshift_Private(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::Redshift::Cluster",
		ResourceID:   "my-cluster-private",
		Region:       "us-east-1",
		Properties:   map[string]any{"IsPubliclyAccessible": false},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.Equal(t, output.AccessLevelPrivate, results[0].AWSResource.AccessLevel)
	assert.False(t, results[0].IsPublic)
}

func TestEvaluateCore_Cognito_SelfSignup(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc",
		Region:       "us-east-1",
		Properties:   map[string]any{"SelfSignupEnabled": true},
	}

	results := collectCore(e, resource)

	require.Len(t, results, 1)
	assert.True(t, results[0].IsPublic)
	assert.Equal(t, output.AccessLevelPublic, results[0].AWSResource.AccessLevel)
}

// --- evaluatePolicy tests ---
//
// These test the shared helper that handles fetch errors, nil policies,
// ARN fallback, and policy evaluation delegation.

func TestEvaluatePolicy_FetchError(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		ARN:          "arn:aws:s3:::my-bucket",
		Properties:   map[string]any{},
	}

	result := e.evaluatePolicy(resource, nil, fmt.Errorf("access denied"), testAccountID)

	assert.Nil(t, result, "fetch error should return nil")
}

func TestEvaluatePolicy_NilPolicy(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		ARN:          "arn:aws:s3:::my-bucket",
		Properties:   map[string]any{},
	}

	result := e.evaluatePolicy(resource, nil, nil, testAccountID)

	assert.Nil(t, result, "nil policy should return nil")
}

func TestEvaluatePolicy_PublicPolicy(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "arn:aws:sns:us-east-1:123456789012:my-topic",
		ARN:          "arn:aws:sns:us-east-1:123456789012:my-topic",
		Properties:   map[string]any{},
	}

	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"sns:Publish"}),
				Resource: types.NewDynaString([]string{"arn:aws:sns:us-east-1:123456789012:my-topic"}),
			},
		},
	}

	result := e.evaluatePolicy(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "sns:Publish")
}

func TestEvaluatePolicy_PrivatePolicy(t *testing.T) {
	e := newTestEvaluator()
	resource := &output.AWSResource{
		ResourceType: "AWS::SQS::Queue",
		ResourceID:   "arn:aws:sqs:us-east-1:123456789012:my-queue",
		ARN:          "arn:aws:sqs:us-east-1:123456789012:my-queue",
		Properties:   map[string]any{},
	}

	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"arn:aws:iam::123456789012:root"}),
				},
				Action:   types.NewDynaString([]string{"sqs:SendMessage"}),
				Resource: types.NewDynaString([]string{"arn:aws:sqs:us-east-1:123456789012:my-queue"}),
			},
		},
	}

	result := e.evaluatePolicy(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.False(t, result.IsPublic, "same-account policy should not be public")
}

func TestEvaluatePolicy_ARNFallbackToResourceID(t *testing.T) {
	e := newTestEvaluator()
	// ARN is empty — evaluatePolicy should fall back to ResourceID
	resource := &output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "arn:aws:sns:us-east-1:123456789012:fallback-topic",
		ARN:          "",
		Properties:   map[string]any{},
	}

	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"sns:Publish"}),
				Resource: types.NewDynaString([]string{"arn:aws:sns:us-east-1:123456789012:fallback-topic"}),
			},
		},
	}

	result := e.evaluatePolicy(resource, policy, nil, testAccountID)

	require.NotNil(t, result)
	assert.True(t, result.IsPublic, "should work with ResourceID when ARN is empty")
}

func TestEvaluatePolicy_EvaluationError(t *testing.T) {
	e := newTestEvaluator()
	// Use an unsupported resource type to trigger evaluation error
	resource := &output.AWSResource{
		ResourceType: "AWS::Foo::Bar",
		ResourceID:   "my-resource",
		ARN:          "arn:aws:foo:us-east-1:123456789012:bar/my-resource",
		Properties:   map[string]any{},
	}

	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"foo:GetBar"}),
				Resource: types.NewDynaString([]string{"*"}),
			},
		},
	}

	result := e.evaluatePolicy(resource, policy, nil, testAccountID)

	assert.Nil(t, result, "evaluation error should return nil")
}
