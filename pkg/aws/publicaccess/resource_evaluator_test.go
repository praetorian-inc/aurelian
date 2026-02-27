package publicaccess

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEvaluator() *ResourceEvaluator {
	return &ResourceEvaluator{}
}

func TestSupportedResourceTypes(t *testing.T) {
	types := SupportedResourceTypes()
	assert.Len(t, types, 8)

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

func TestSetResult(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-123",
		Properties:   map[string]any{},
	}

	result := &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"ec2:NetworkAccess"},
		EvaluationReasons: []string{"has public IP"},
	}

	setResult(resource, result)

	_, ok := resource.Properties["PublicAccessResult"]
	assert.True(t, ok, "PublicAccessResult should be set in properties")
}

// --- Lambda evaluateLambdaAccess integration tests ---
//
// These tests exercise every combination of resource-policy outcome and
// FunctionUrl AuthType to verify that both checks run independently and
// their results are merged correctly.

const (
	testAccountID   = "123456789012"
	testLambdaARN   = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
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
