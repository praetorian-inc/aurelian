package aws

import (
	"testing"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/stretchr/testify/assert"
)

func createRequestContext(principalArn string) *RequestContext {
	return &RequestContext{
		PrincipalArn:    principalArn,
		SourceIp:        "203.0.113.0",
		UserAgent:       "aws-cli/1.16.312",
		CurrentTime:     time.Now(),
		SecureTransport: true,
		ResourceTags: map[string]string{
			"environment": "production",
			"project":     "website",
		},
		RequestTags: map[string]string{
			"costcenter": "12345",
		},
		PrincipalOrgId: "o-1234567",
		AccountId:      "111122223333",
		RequestParameters: map[string]string{
			"PrincipalOrgPaths": "o-1234567/r-ab12/ou-ab12-11111111/",
		},
	}
}

func TestPolicyEvaluator_BasicIdentityPolicy(t *testing.T) {
	identityStatements := &types.PolicyStatementList{
		{
			Effect: "Allow",
			Action: types.NewDynaString([]string{"s3:GetObject"}),
			Resource: types.NewDynaString([]string{
				"arn:aws:s3::111122223333:example-bucket/*",
			}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{})
	req := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result, err := evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.False(t, result.CrossAccountAccess)

	identityStatements = &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	req = &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result, err = evaluator.Evaluate(req)
	assert.NoError(t, err)
	assert.True(t, result.Allowed)

	identityStatements = &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}
}

func TestPolicyEvaluator_ExplicitDenyOverridesAllow(t *testing.T) {
	identityStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
		{
			Effect:   "Deny",
			Action:   types.NewDynaString([]string{"s3:DeleteObject"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{})

	req := &EvaluationRequest{
		Action:             "s3:DeleteObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result, err := evaluator.Evaluate(req)
	assert.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestPolicyEvaluator_PermissionBoundary(t *testing.T) {
	// Identity policy allows S3 and EC2
	identityStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*", "ec2:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	// Boundary only allows S3
	boundaryStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{})

	// Test 1: Action allowed within boundary
	req1 := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
		BoundaryStatements: boundaryStatements,
	}

	result1, err := evaluator.Evaluate(req1)
	t.Log(result1)
	assert.NoError(t, err)
	assert.True(t, result1.Allowed) // Allowed by both identity policy and boundary

	// Test 2: Action denied - allowed by identity but not boundary
	req2 := &EvaluationRequest{
		Action:             "ec2:RunInstances",
		Resource:           "arn:aws:ec2:us-west-2:111122223333:instance/*",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
		BoundaryStatements: boundaryStatements,
	}

	result2, err := evaluator.Evaluate(req2)
	assert.NoError(t, err)
	assert.False(t, result2.Allowed)
	assert.Equal(t, "Denied by permission boundary", result2.EvaluationDetails)

	// Test 3: No boundary - falls back to identity policy evaluation
	req3 := &EvaluationRequest{
		Action:             "ec2:RunInstances",
		Resource:           "arn:aws:ec2:us-west-2:111122223333:instance/*",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result3, err := evaluator.Evaluate(req3)
	assert.NoError(t, err)
	assert.True(t, result3.Allowed) // Allowed by identity policy

	// Test 3: No boundary - falls back to identity policy evaluation
	req4 := &EvaluationRequest{
		Action:             "ec2:RunInstances",
		Resource:           "arn:aws:ec2:us-west-2:111122223333:instance/*",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
		BoundaryStatements: &types.PolicyStatementList{},
	}

	result4, err := evaluator.Evaluate(req4)
	t.Log(result4)
	assert.NoError(t, err)
	assert.True(t, result4.Allowed) // Allowed by identity policy

}

func TestPolicyEvaluator_ServiceControlPolicy(t *testing.T) {
	identityStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	scpStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
		{
			Effect:   "Deny",
			Action:   types.NewDynaString([]string{"s3:DeleteBucket"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{
		SCP: scpStatements,
	})

	// Test allowed action
	req1 := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result1, err := evaluator.Evaluate(req1)
	assert.NoError(t, err)
	assert.True(t, result1.Allowed)

	// Test denied action by SCP
	req2 := &EvaluationRequest{
		Action:             "s3:DeleteBucket",
		Resource:           "arn:aws:s3::111122223333:example-bucket",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result2, err := evaluator.Evaluate(req2)
	assert.NoError(t, err)
	assert.False(t, result2.Allowed)
	assert.Equal(t, "Explicitly denied by SCP", result2.EvaluationDetails)
}

func TestPolicyEvaluator_ResourceControlPolicy(t *testing.T) {
	// Set up same policies but add debug prints
	identityStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	rcpStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
		{
			Effect:   "Deny",
			Action:   types.NewDynaString([]string{"s3:PutObject"}),
			Resource: types.NewDynaString([]string{"*"}),
			Condition: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalOrgID": {"o-1234567"},
				},
			},
		},
	}

	t.Logf("Identity Statements: %+v", identityStatements)
	t.Logf("RCP Statements: %+v", rcpStatements)

	evaluator := NewPolicyEvaluator(&PolicyData{RCP: rcpStatements})

	// Test outside-org request
	ctx := createRequestContext("arn:aws:iam::999988887777:user/external-user")
	ctx.PrincipalOrgId = "o-9999999"

	t.Logf("Request Context: %+v", ctx)

	req := &EvaluationRequest{
		Action:             "s3:PutObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            ctx,
		IdentityStatements: identityStatements,
	}

	result, err := evaluator.Evaluate(req)
	t.Logf("Evaluation Result: %+v", result)
	t.Logf("Evaluation Error: %v", err)
	if result != nil && result.PolicyResult != nil {
		t.Logf("RCP Evaluations: %+v", result.PolicyResult.Evaluations[EvalTypeRCP])
	}

	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "Explicitly denied by RCP", result.EvaluationDetails)
}

func TestPolicyEvaluator_ResourceBasedPolicy(t *testing.T) {
	identityStatements := &types.PolicyStatementList{}

	resource := "arn:aws:s3::111122223333:example-bucket/file.txt"
	resourcePolicies := map[string]*types.Policy{
		resource: {
			Id:      "Policy1",
			Version: "2012-10-17",
			Statement: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: types.NewDynaString([]string{"arn:aws:iam::111122223333:user/test-user"}),
					},
					Action:   types.NewDynaString([]string{"s3:GetObject"}),
					Resource: types.NewDynaString([]string{resource}),
				},
			},
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{ResourcePolicies: resourcePolicies})

	// Test same-account access
	req1 := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           resource,
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result1, err := evaluator.Evaluate(req1)
	assert.NoError(t, err)
	assert.True(t, result1.Allowed)
	assert.False(t, result1.CrossAccountAccess)

	// Test cross-account access
	req2 := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           resource,
		Context:            createRequestContext("arn:aws:iam::999988887777:user/other-user"),
		IdentityStatements: identityStatements,
	}

	result2, err := evaluator.Evaluate(req2)
	t.Logf("Result: %+v", result2)
	assert.NoError(t, err)
	assert.False(t, result2.Allowed)
	assert.True(t, result2.CrossAccountAccess)
}

func TestPolicyEvaluator_SCPDenyS3PublicAccess(t *testing.T) {
	// Define the SCP policy statements
	scpStatements := &types.PolicyStatementList{
		{
			Sid:      "p-FullAWSAccess",
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
		{
			Sid:    "BlockChangesToS3PublicAccess",
			Effect: "Deny",
			Action: types.NewDynaString([]string{
				"s3:PutBucketPublicAccessBlock",
				"s3:PutBucketPolicy",
				"s3:PutBucketAcl",
				"s3:PutAccountPublicAccessBlock",
			}),
			Resource: types.NewDynaString([]string{"*"}),
			Condition: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalArn": []string{
						"arn:aws:iam::111122223333:role/foo-dev-us-west-2",
						"arn:aws:iam::222233334444:role/foo-prod-us-west-2",
					},
				},
			},
		},
	}
	identity := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{SCP: scpStatements})

	bucket := "arn:aws:s3::111122223333:example-bucket"
	tests := []struct {
		name             string
		principalArn     string
		action           string
		resource         string
		wantAllowed      bool
		wantExplicitDeny bool
	}{
		{
			name:             "Allowed role",
			principalArn:     "arn:aws:iam::111122223333:role/foo-dev-us-west-2",
			action:           "s3:PutBucketPolicy",
			resource:         bucket,
			wantAllowed:      true,
			wantExplicitDeny: false,
		},
		{
			name:             "Denied different role",
			principalArn:     "arn:aws:iam::111122223333:role/some-other-role",
			action:           "s3:PutBucketPolicy",
			resource:         bucket,
			wantAllowed:      false,
			wantExplicitDeny: true,
		},
		{
			name:             "Allowed staging role",
			principalArn:     "arn:aws:iam::222233334444:role/foo-prod-us-west-2",
			resource:         "arn:aws:s3::222233334444:example-bucket",
			action:           "s3:PutBucketAcl",
			wantAllowed:      true,
			wantExplicitDeny: false,
		},
		{
			name:             "Denied unmatched account",
			principalArn:     "arn:aws:iam::999999999999:role/foo-dev-us-west-2",
			action:           "s3:PutBucketPublicAccessBlock",
			resource:         bucket,
			wantAllowed:      false,
			wantExplicitDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:             tt.action,
				Resource:           tt.resource,
				Context:            createRequestContext(tt.principalArn),
				IdentityStatements: identity,
			}

			result, err := evaluator.Evaluate(req)
			assert.NoError(t, err)
			t.Log(t.Name())
			t.Log(result)
			t.Logf("PrincipalArn: %s, Action: %s, Allowed: %v, WantAllowed: %v", tt.principalArn, tt.action, result.Allowed, tt.wantAllowed)

			// Add more detailed assertion logging
			t.Logf("Allowed assertion: expected=%v, got=%v", tt.wantAllowed, result.Allowed)
			assert.Equal(t, tt.wantAllowed, result.Allowed)

			// Verify SCP evaluations separately
			// scpEvals := result.PolicyResult.Evaluations[EvalTypeSCP]
			// if assert.NotEmpty(t, scpEvals, "Expected non-empty SCP evaluations") {
			// 	t.Logf("ExplicitDeny assertion: expected=%v, got=%v", tt.wantExplicitDeny, scpEvals[0].ExplicitDeny)
			// 	assert.Equal(t, tt.wantExplicitDeny, scpEvals[0].ExplicitDeny)
			// }
		})
	}
}

func TestPolicyEvaluator_AssumeRolePolicyDocument(t *testing.T) {
	// Define the assume role trust document
	assumeRolePolicy := &types.PolicyStatementList{
		{
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: types.NewDynaString([]string{
					"arn:aws:iam::111122223333:root",
					"arn:aws:iam::123456789012:role/cross-account",
				}),
				Service: types.NewDynaString([]string{"glue.amazonaws.com"}),
			},
			Action:    types.NewDynaString([]string{"sts:AssumeRole"}),
			Condition: &types.Condition{},
			OriginArn: "arn:aws:iam::111122223333:role/role-name/assume-role-policy",
			Resource:  types.NewDynaString([]string{"arn:aws:iam::111122223333:role/role-name"}), // we need to inject this into the ARPD
		},
	}

	identity := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{})

	tests := []struct {
		name             string
		principalArn     string
		action           string
		resource         string
		wantAllowed      bool
		wantExplicitDeny bool
	}{
		{
			name:             "Allowed role",
			principalArn:     "arn:aws:iam::111122223333:user/test-user",
			action:           "sts:AssumeRole",
			resource:         "arn:aws:iam::111122223333:role/role-name",
			wantAllowed:      true,
			wantExplicitDeny: false,
		},
		{
			name:             "Denied different account",
			principalArn:     "arn:aws:iam::111122223334:user/some-other-user",
			action:           "sts:AssumeRole",
			resource:         "arn:aws:iam::111122223333:role/role-name",
			wantAllowed:      false,
			wantExplicitDeny: true,
		},
		{
			name:             "Allowed cross-account role",
			principalArn:     "arn:aws:iam::123456789012:role/cross-account",
			action:           "sts:AssumeRole",
			resource:         "arn:aws:iam::111122223333:role/role-name",
			wantAllowed:      true,
			wantExplicitDeny: false,
		},
		{
			name:             "Service",
			principalArn:     "glue.amazonaws.com",
			action:           "sts:AssumeRole",
			resource:         "arn:aws:iam::111122223333:role/role-name",
			wantAllowed:      true,
			wantExplicitDeny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:             tt.action,
				Resource:           tt.resource,
				Context:            createRequestContext(tt.principalArn),
				IdentityStatements: identity,
				BoundaryStatements: assumeRolePolicy,
			}

			result, err := evaluator.Evaluate(req)
			assert.NoError(t, err)
			t.Log(t.Name())
			t.Log(result)
			t.Logf("PrincipalArn: %s, Action: %s, Allowed: %v, WantAllowed: %v", tt.principalArn, tt.action, result.Allowed, tt.wantAllowed)

			// Add more detailed assertion logging
			t.Logf("Allowed assertion: expected=%v, got=%v", tt.wantAllowed, result.Allowed)
			assert.Equal(t, tt.wantAllowed, result.Allowed)

		})
	}

}
