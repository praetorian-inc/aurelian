package aws

import (
	"testing"
	"time"

	"encoding/json"

	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/stretchr/testify/assert"
)

func createRequestContext(principalArn string) *RequestContext {
	return &RequestContext{
		PrincipalArn:    principalArn,
		SourceIP:        "203.0.113.0",
		UserAgent:       "aws-cli/1.16.312",
		CurrentTime:     time.Now(),
		SecureTransport: Bool(true),
		ResourceTags: map[string]string{
			"environment": "production",
			"project":     "website",
		},
		RequestTags: map[string]string{
			"costcenter": "12345",
		},
		PrincipalOrgID:   "o-1234567",
		PrincipalAccount: "111122223333",
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
		Resource:           "ec2.amazonaws.com",
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
		Resource:           "ec2.amazonaws.com",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result3, err := evaluator.Evaluate(req3)
	assert.NoError(t, err)
	assert.True(t, result3.Allowed) // Allowed by identity policy

	// Test 3: No boundary - falls back to identity policy evaluation
	req4 := &EvaluationRequest{
		Action:             "ec2:RunInstances",
		Resource:           "ec2.amazonaws.com",
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

	// Create OrgPolicies structure with both allow and deny statements
	orgPolicies := &orgpolicies.OrgPolicies{
		SCPs: []orgpolicies.PolicyData{
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("FullAWSAccess"),
					Id:   aws.String("p-FullAWSAccess"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
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
					},
				},
				Targets: []orgpolicies.PolicyTarget{
					{
						TargetID: "o-1234567",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		RCPs: []orgpolicies.PolicyData{},
		Targets: []orgpolicies.OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "o-1234567",
				Type: "ROOT",
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
					ParentPolicies: []orgpolicies.ParentPolicy{},
				},
			},
			{
				Name: "Test Account",
				ID:   "111122223333",
				Type: "ACCOUNT",
				Account: &orgpolicies.Account{
					ID:     "111122223333",
					Name:   "Test Account",
					Email:  "test@example.com",
					Status: "ACTIVE",
				},
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []orgpolicies.ParentPolicy{
						{
							Name:     "Root",
							ID:       "o-1234567",
							Policies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
						},
					},
				},
				RCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []orgpolicies.ParentPolicy{},
				},
			},
		},
	}

	// Add the test account to the Targets list
	orgPolicies.Targets = append(orgPolicies.Targets, orgpolicies.OrgPolicyTarget{
		Name: "Test Account",
		ID:   "999999999999",
		Type: "ACCOUNT",
		Account: &orgpolicies.Account{
			ID:     "999999999999",
			Name:   "Test Account",
			Email:  "test@example.com",
			Status: "ACTIVE",
		},
		SCPs: orgpolicies.OrgPolicyTargetPolicies{
			DirectPolicies: []string{},
			ParentPolicies: []orgpolicies.ParentPolicy{
				{
					Name:     "Root",
					ID:       "o-1234567",
					Policies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
				},
			},
		},
	})

	evaluator := NewPolicyEvaluator(&PolicyData{
		OrgPolicies: orgPolicies,
	})

	// Test 1: Allowed action
	ctx := createRequestContext("arn:aws:iam::111122223333:user/test-user")
	ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:example-bucket/file.txt")
	req1 := &EvaluationRequest{
		Action:             "s3:GetObject",
		Resource:           "arn:aws:s3::111122223333:example-bucket/file.txt",
		Context:            ctx,
		IdentityStatements: identityStatements,
	}

	result1, err := evaluator.Evaluate(req1)
	assert.NoError(t, err)
	assert.True(t, result1.Allowed)

	// Test 2: Explicitly denied action by SCP

	req2 := &EvaluationRequest{
		Action:             "s3:DeleteBucket",
		Resource:           "arn:aws:s3::111122223333:example-bucket",
		Context:            ctx,
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

	orgPolicies := orgpolicies.NewDefaultOrgPolicies()
	orgPolicies.RCPs = []orgpolicies.PolicyData{
		{
			PolicySummary: awstypes.PolicySummary{
				Name: aws.String("TestRCP"),
				Id:   aws.String("p-testrcp"),
				Arn:  aws.String("arn:aws:organizations::aws:policy/resource_control_policy/p-testrcp"),
			},
			PolicyContent: types.Policy{
				Version: "2012-10-17",
				Statement: &types.PolicyStatementList{
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
				},
			},
			Targets: []orgpolicies.PolicyTarget{
				{
					TargetID: "r-root",
					Name:     "Root",
					Type:     "ROOT",
				},
			},
		},
	}

	// Add the target account to the Targets list
	orgPolicies.Targets = append(orgPolicies.Targets, orgpolicies.OrgPolicyTarget{
		Name: "Resource Account",
		ID:   "111122223333",
		Type: "ACCOUNT",
		Account: &orgpolicies.Account{
			ID:     "111122223333",
			Name:   "Resource Account",
			Email:  "resource@example.com",
			Status: "ACTIVE",
		},
		RCPs: orgpolicies.OrgPolicyTargetPolicies{
			DirectPolicies: []string{},
			ParentPolicies: []orgpolicies.ParentPolicy{
				{
					Name:     "Root",
					ID:       "r-root",
					Policies: []string{"arn:aws:organizations::aws:policy/resource_control_policy/p-testrcp"},
				},
			},
		},
	})

	// Create a resource policy to ensure the external user has basic access
	resourcePolicy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"s3:PutObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3::111122223333:example-bucket/file.txt"}),
			},
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{
		OrgPolicies: orgPolicies,
		ResourcePolicies: map[string]*types.Policy{
			"arn:aws:s3::111122223333:example-bucket/file.txt": resourcePolicy,
		},
	})

	// Test outside-org request
	ctx := createRequestContext("arn:aws:iam::999988887777:user/external-user")
	ctx.PrincipalOrgID = "o-9999999"

	// Set the resource account ID and populate condition keys
	resource := "arn:aws:s3::111122223333:example-bucket/file.txt"
	ctx.PopulateDefaultRequestConditionKeys(resource)

	t.Logf("Request Context: %+v", ctx)

	req := &EvaluationRequest{
		Action:             "s3:PutObject",
		Resource:           resource,
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
	// Create OrgPolicies structure with both allow and deny statements
	orgPolicies := &orgpolicies.OrgPolicies{
		SCPs: []orgpolicies.PolicyData{
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("FullAWSAccess"),
					Id:   aws.String("p-FullAWSAccess"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
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
					},
				},
				Targets: []orgpolicies.PolicyTarget{
					{
						TargetID: "o-1234567",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		Targets: []orgpolicies.OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "o-1234567",
				Type: "ROOT",
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
					ParentPolicies: []orgpolicies.ParentPolicy{},
				},
			},
			{
				Name: "Test Account",
				ID:   "111122223333",
				Type: "ACCOUNT",
				Account: &orgpolicies.Account{
					ID:     "111122223333",
					Name:   "Test Account",
					Email:  "test@example.com",
					Status: "ACTIVE",
				},
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []orgpolicies.ParentPolicy{
						{
							Name:     "Root",
							ID:       "o-1234567",
							Policies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
						},
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

	evaluator := NewPolicyEvaluator(&PolicyData{
		OrgPolicies: orgPolicies,
	})

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
			ctx := createRequestContext(tt.principalArn)
			ctx.PopulateDefaultRequestConditionKeys(tt.resource)
			req := &EvaluationRequest{
				Action:             tt.action,
				Resource:           tt.resource,
				Context:            ctx,
				IdentityStatements: identity,
			}

			result, err := evaluator.Evaluate(req)
			assert.NoError(t, err)
			t.Log(t.Name())
			t.Log(result)
			t.Logf("PrincipalArn: %s, Action: %s, Allowed: %v, WantAllowed: %v", tt.principalArn, tt.action, result.Allowed, tt.wantAllowed)

			assert.Equal(t, tt.wantAllowed, result.Allowed)
			if !tt.wantAllowed {
				assert.Equal(t, "Explicitly denied by SCP", result.EvaluationDetails)
			}
		})
	}
}

func TestPolicyEvaluator_SCPRegionGuardRails(t *testing.T) {
	// Create OrgPolicies structure with region guardrails
	orgPolicies := &orgpolicies.OrgPolicies{
		SCPs: []orgpolicies.PolicyData{
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("RegionGuardrails"),
					Id:   aws.String("p-RegionGuardrails"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-RegionGuardrails"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Sid:      "p-FullAWSAccess",
							Effect:   "Allow",
							Action:   types.NewDynaString([]string{"*"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
						{
							Sid:      "DenyNonUsRegions",
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"*"}),
							Resource: types.NewDynaString([]string{"*"}),
							Condition: &types.Condition{
								"StringNotEquals": {
									"aws:RequestedRegion": []string{
										"us-east-1",
										"us-east-2",
										"us-west-1",
										"us-west-2",
										"us-gov-east-1",
										"us-gov-west-1",
									},
								},
							},
						},
					},
				},
				Targets: []orgpolicies.PolicyTarget{
					{
						TargetID: "o-1234567",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		Targets: []orgpolicies.OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "o-1234567",
				Type: "ROOT",
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-RegionGuardrails"},
					ParentPolicies: []orgpolicies.ParentPolicy{},
				},
			},
			{
				Name: "Test Account",
				ID:   "111122223333",
				Type: "ACCOUNT",
				Account: &orgpolicies.Account{
					ID:     "111122223333",
					Name:   "Test Account",
					Email:  "test@example.com",
					Status: "ACTIVE",
				},
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []orgpolicies.ParentPolicy{
						{
							Name:     "Root",
							ID:       "o-1234567",
							Policies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-RegionGuardrails"},
						},
					},
				},
			},
		},
	}

	identity := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	tests := []struct {
		name         string
		principalArn string
		action       string
		resource     string
		eval         EvaluationResult
	}{
		{
			"Allowed in us-east-1",
			"arn:aws:iam::111122223333:user/test-user",
			"s3:GetObject",
			"arn:aws:s3::111122223333:example-bucket/file.txt",
			EvaluationResult{
				Allowed: true,
			},
		},
		{
			"Denied in eu-west-1",
			"arn:aws:iam::111122223333:user/test-user",
			"s3:GetObject",
			"arn:aws:lambda:eu-west-1:111122223333:function:example-function",
			EvaluationResult{
				Allowed:           false,
				EvaluationDetails: "Explicitly denied by SCP",
			},
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{
		OrgPolicies: orgPolicies,
	})

	// Add the test account to the Targets list
	orgPolicies.Targets = append(orgPolicies.Targets, orgpolicies.OrgPolicyTarget{
		Name: "Test Account",
		ID:   "111122223333",
		Type: "ACCOUNT",
		Account: &orgpolicies.Account{
			ID:     "111122223333",
			Name:   "Test Account",
			Email:  "test@example.com",
			Status: "ACTIVE",
		},
		SCPs: orgpolicies.OrgPolicyTargetPolicies{
			DirectPolicies: []string{},
			ParentPolicies: []orgpolicies.ParentPolicy{
				{
					Name:     "Root",
					ID:       "o-1234567",
					Policies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-RegionGuardrails"},
				},
			},
		},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Action:             tt.action,
				Resource:           tt.resource,
				Context:            createRequestContext(tt.principalArn),
				IdentityStatements: identity,
			}

			req.Context.PopulateDefaultRequestConditionKeys(tt.resource)

			result, err := evaluator.Evaluate(req)
			assert.NoError(t, err)
			t.Log(t.Name())
			t.Log(result)
			assert.Equal(t, tt.eval.Allowed, result.Allowed)
			if !tt.eval.Allowed {
				assert.Equal(t, tt.eval.EvaluationDetails, result.EvaluationDetails)
			}
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

func TestPolicyEvaluator_SNSResourcePolicy(t *testing.T) {
	// Create the SNS resource policy

	rawPolicy := `{
  "Version": "2008-10-17",
  "Id": "__default_policy_ID",
  "Statement": [
    {
      "Sid": "__default_statement_ID",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "SNS:Publish",
        "SNS:RemovePermission",
        "SNS:SetTopicAttributes",
        "SNS:DeleteTopic",
        "SNS:ListSubscriptionsByTopic",
        "SNS:GetTopicAttributes",
        "SNS:AddPermission",
        "SNS:Subscribe"
      ],
      "Resource": "arn:aws:sns:us-east-1:123456789012:PublicTopic",
      "Condition": {
        "StringEquals": {
          "AWS:SourceOwner": "123456789012"
        }
      }
    }
  ]
}`
	var snsPolicy types.Policy
	err := json.Unmarshal([]byte(rawPolicy), &snsPolicy)
	assert.NoError(t, err)

	// Create the PolicyData with the resource policy
	policyData := &PolicyData{
		ResourcePolicies: map[string]*types.Policy{
			"arn:aws:sns:us-east-1:123456789012:PublicTopic": &snsPolicy,
		},
	}

	// Create evaluator with the policy data
	evaluator := NewPolicyEvaluator(policyData)

	// Test with matching SourceOwner - should be allowed
	ctx := createRequestContext("arn:aws:iam::123456789012:user/test-user")
	ctx.SourceOwner = "123456789012"

	req := &EvaluationRequest{
		Action:   "SNS:Publish",
		Resource: "arn:aws:sns:us-east-1:123456789012:PublicTopic",
		Context:  ctx,
	}

	result, err := evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.False(t, result.CrossAccountAccess)

	// Test with non-matching SourceOwner - should be denied
	ctx = createRequestContext("arn:aws:iam::111122223333:user/test-user")
	ctx.SourceOwner = "111122223333"

	req = &EvaluationRequest{
		Action:   "SNS:Publish",
		Resource: "arn:aws:sns:us-east-1:123456789012:PublicTopic",
		Context:  ctx,
	}

	result, err = evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.False(t, result.Allowed, "Access should be denied due to non-matching SourceOwner condition")

	// Test with matching SourceOwner but non-matching action - should be denied
	ctx = createRequestContext("arn:aws:iam::123456789012:user/test-user")
	ctx.RequestParameters["AWS:SourceOwner"] = "123456789012"

	req = &EvaluationRequest{
		Action:   "SNS:CreateTopic", // Action not in policy
		Resource: "arn:aws:sns:us-east-1:123456789012:PublicTopic",
		Context:  ctx,
	}

	result, err = evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.False(t, result.Allowed, "Access should be denied due to non-matching action")

	// Test with matching SourceOwner but non-matching resource - should be denied
	ctx = createRequestContext("arn:aws:iam::123456789012:user/test-user")
	ctx.RequestParameters["AWS:SourceOwner"] = "123456789012"

	req = &EvaluationRequest{
		Action:   "SNS:Publish",
		Resource: "arn:aws:sns:us-east-1:123456789012:DifferentTopic", // Resource not matching
		Context:  ctx,
	}

	result, err = evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.False(t, result.Allowed, "Access should be denied due to non-matching resource")
}

func TestPolicyEvaluator_CreateWithServiceAsResource(t *testing.T) {
	identityStatements := &types.PolicyStatementList{
		{
			Effect: "Allow",
			Action: types.NewDynaString([]string{"lambda:CreateFunction"}),
			Resource: types.NewDynaString([]string{
				"*",
			}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{})
	req := &EvaluationRequest{
		Action:             "lambda:CreateFunction",
		Resource:           "lambda.amazonaws.com",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result, err := evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.False(t, result.CrossAccountAccess)

	evaluator = NewPolicyEvaluator(&PolicyData{})
	req = &EvaluationRequest{
		Action:             "lambda:CreateFunction",
		Resource:           "arn:aws:lambda:us-east-1:111122223333:function:my-function",
		Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
		IdentityStatements: identityStatements,
	}

	result, err = evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestPolicyEvaluator_SCPServiceLinkedRole(t *testing.T) {
	// Create OrgPolicies structure with deny bedrock:* policy
	orgPolicies := &orgpolicies.OrgPolicies{
		SCPs: []orgpolicies.PolicyData{
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("FullAWSAccess"),
					Id:   aws.String("p-FullAWSAccess"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Effect:   "Allow",
							Action:   types.NewDynaString([]string{"*"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []orgpolicies.PolicyTarget{
					{
						TargetID: "o-1234567",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("DenyBedrock"),
					Id:   aws.String("p-DenyBedrock"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-DenyBedrock"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Effect:   "Deny",
							Action:   types.NewDynaString([]string{"bedrock:*"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []orgpolicies.PolicyTarget{
					{
						TargetID: "o-1234567",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		Targets: []orgpolicies.OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "o-1234567",
				Type: "ROOT",
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{
						"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
						"arn:aws:organizations::aws:policy/service_control_policy/p-DenyBedrock",
					},
					ParentPolicies: []orgpolicies.ParentPolicy{},
				},
			},
			{
				Name: "Test Account",
				ID:   "111122223333",
				Type: "ACCOUNT",
				Account: &orgpolicies.Account{
					ID:     "111122223333",
					Name:   "Test Account",
					Email:  "test@example.com",
					Status: "ACTIVE",
				},
				SCPs: orgpolicies.OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []orgpolicies.ParentPolicy{
						{
							Name: "Root",
							ID:   "o-1234567",
							Policies: []string{
								"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
								"arn:aws:organizations::aws:policy/service_control_policy/p-DenyBedrock",
							},
						},
					},
				},
			},
		},
	}

	identityStatements := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   types.NewDynaString([]string{"bedrock:*"}),
			Resource: types.NewDynaString([]string{"*"}),
		},
	}

	evaluator := NewPolicyEvaluator(&PolicyData{
		OrgPolicies: orgPolicies,
	})

	// Test regular principal - should be denied by SCP
	ctx := createRequestContext("arn:aws:iam::111122223333:user/test-user")
	ctx.PrincipalOrgID = "o-1234567"
	req := &EvaluationRequest{
		Action:             "bedrock:InvokeModel",
		Resource:           "arn:aws:bedrock:us-east-1:111122223333:agent/QOYTA2YG0G",
		Context:            ctx,
		IdentityStatements: identityStatements,
	}

	result, err := evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "Explicitly denied by SCP", result.EvaluationDetails)

	// Test service-linked role - should be allowed despite SCP deny
	ctx = createRequestContext("arn:aws:iam::111122223333:role/aws-service-role/bedrock.amazonaws.com/AWSServiceRoleForBedrock")
	ctx.PrincipalOrgID = "o-1234567"
	req = &EvaluationRequest{
		Action:             "bedrock:InvokeModel",
		Resource:           "arn:aws:bedrock:us-east-1:111122223333:agent/QOYTA2YG0G",
		Context:            ctx,
		IdentityStatements: identityStatements,
	}

	result, err = evaluator.Evaluate(req)
	t.Log(result)
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestHasExplicitPrincipalAllow(t *testing.T) {
	evaluator := NewPolicyEvaluator(&PolicyData{})

	tests := []struct {
		name         string
		statements   *types.PolicyStatementList
		principalArn string
		want         bool
	}{
		{
			name: "Direct ARN match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::111122223333:user/test-user"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         true,
		},
		{
			name: "Wildcard match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"*"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         true,
		},
		{
			name: "Root account match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::111122223333:root"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         true,
		},
		{
			name: "Account wildcard match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::111122223333:*"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         true,
		},
		{
			name: "No match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::999988887777:user/other-user"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         false,
		},
		{
			name: "Deny statement",
			statements: &types.PolicyStatementList{
				{
					Effect: "Deny",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::111122223333:user/test-user"},
					},
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         false,
		},
		{
			name: "No Principal",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
				},
			},
			principalArn: "arn:aws:iam::111122223333:user/test-user",
			want:         false,
		},
		{
			name: "AWS Service Principal Match",
			statements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						Service: &types.DynaString{"glue.amazonaws.com"},
					},
				},
			},
			principalArn: "glue.amazonaws.com",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluator.hasExplicitPrincipalAllow(tt.statements, tt.principalArn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPolicyEvaluator_SSMDocumentRestrictions(t *testing.T) {
	tests := []struct {
		name                      string
		action                    string
		identityStatements        *types.PolicyStatementList
		wantDocumentRestrictions  []string
		wantAllowed               bool
	}{
		{
			name:   "SSM SendCommand with wildcard document (HIGH RISK)",
			action: "ssm:SendCommand",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:SendCommand"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
						"*", // Wildcard allows any document
					}),
				},
			},
			wantDocumentRestrictions: []string{"*"},
			wantAllowed:              true,
		},
		{
			name:   "SSM SendCommand with RunShellScript document (HIGH RISK)",
			action: "ssm:SendCommand",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:SendCommand"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
						"arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
					}),
				},
			},
			wantDocumentRestrictions: []string{"arn:aws:ssm:us-east-1::document/AWS-RunShellScript"},
			wantAllowed:              true,
		},
		{
			name:   "SSM SendCommand with restricted safe document (LOW RISK)",
			action: "ssm:SendCommand",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:SendCommand"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
						"arn:aws:ssm:us-east-1::document/AWS-ConfigureAWSPackage",
					}),
				},
			},
			wantDocumentRestrictions: []string{"arn:aws:ssm:us-east-1::document/AWS-ConfigureAWSPackage"},
			wantAllowed:              true,
		},
		{
			name:   "SSM SendCommand with multiple documents including RunShellScript",
			action: "ssm:SendCommand",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:SendCommand"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
						"arn:aws:ssm:us-east-1::document/AWS-ConfigureAWSPackage",
						"arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
					}),
				},
			},
			wantDocumentRestrictions: []string{
				"arn:aws:ssm:us-east-1::document/AWS-ConfigureAWSPackage",
				"arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
			},
			wantAllowed: true,
		},
		{
			name:   "SSM SendCommand with only instance resource (no document specified)",
			action: "ssm:SendCommand",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:SendCommand"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
					}),
				},
			},
			wantDocumentRestrictions: []string{}, // No documents specified = not explicitly restricted
			wantAllowed:              true,
		},
		{
			name:   "SSM StartSession (no document restrictions expected)",
			action: "ssm:StartSession",
			identityStatements: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Action: types.NewDynaString([]string{"ssm:StartSession"}),
					Resource: types.NewDynaString([]string{
						"arn:aws:ec2:us-east-1:111122223333:instance/*",
					}),
				},
			},
			wantDocumentRestrictions: nil, // StartSession doesn't use documents
			wantAllowed:              true,
		},
		{
			name:   "Non-SSM action (no document restrictions)",
			action: "s3:GetObject",
			identityStatements: &types.PolicyStatementList{
				{
					Effect:   "Allow",
					Action:   types.NewDynaString([]string{"s3:*"}),
					Resource: types.NewDynaString([]string{"*"}),
				},
			},
			wantDocumentRestrictions: nil,
			wantAllowed:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewPolicyEvaluator(&PolicyData{})

			// Choose an appropriate resource based on the action
			resource := "arn:aws:ec2:us-east-1:111122223333:instance/i-1234567890abcdef0"
			if tt.action == "s3:GetObject" {
				resource = "arn:aws:s3::111122223333:example-bucket/file.txt"
			}

			req := &EvaluationRequest{
				Action:             tt.action,
				Resource:           resource,
				Context:            createRequestContext("arn:aws:iam::111122223333:user/test-user"),
				IdentityStatements: tt.identityStatements,
			}

			result, err := evaluator.Evaluate(req)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, result.Allowed)

			// Check document restrictions
			if tt.wantDocumentRestrictions == nil {
				assert.Nil(t, result.SSMDocumentRestrictions, "Expected no SSM document restrictions")
			} else {
				assert.Equal(t, len(tt.wantDocumentRestrictions), len(result.SSMDocumentRestrictions),
					"Document restrictions count mismatch")
				if len(result.SSMDocumentRestrictions) == len(tt.wantDocumentRestrictions) {
					for i, expectedDoc := range tt.wantDocumentRestrictions {
						assert.Equal(t, expectedDoc, result.SSMDocumentRestrictions[i],
							"Document restriction mismatch at index %d", i)
					}
				}
			}

			// Log for debugging
			t.Logf("Action: %s", tt.action)
			t.Logf("Allowed: %v", result.Allowed)
			t.Logf("Document Restrictions: %v", result.SSMDocumentRestrictions)
		})
	}
}
