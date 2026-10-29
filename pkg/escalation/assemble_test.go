package escalation

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssemble_ProducesValidModel(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	coverage := NewCoverageTracker()
	coverage.MarkIAMGAAD()
	coverage.MarkAttempted("AWS::Lambda::Function")
	coverage.MarkAttempted("AWS::EC2::Instance")
	coverage.MarkAttempted("AWS::S3::Bucket")

	m, err := Assemble(AssembleInput{
		GAAD:             gaad,
		Resources:        resources,
		Coverage:         coverage,
		PermissionFormat: "policy_summary",
	})
	require.NoError(t, err)

	assert.Equal(t, ModelVersion, m.Version)
	assert.NotEmpty(t, m.Principals)
	assert.NotEmpty(t, m.Resources)
	assert.NotEmpty(t, m.StructuralFacts)
	assert.NotEmpty(t, m.ResourcePolicies)
	assert.Equal(t, PermSourcePolicySummary, m.PermissionSource.Type)
	assert.NotEmpty(t, m.PermissionSource.Entries)
	assert.NotNil(t, m.CollectionCoverage)
	assert.NotNil(t, m.CollectionCoverage["111111111111"])
	assert.True(t, m.CollectionCoverage["111111111111"].IAMGAAD)
	assert.Equal(t, GoalReachAdmin, m.Goal.Type)
	assert.Equal(t, "*", m.Goal.Attacker)

	// Accounts
	require.Len(t, m.Accounts, 1)
	assert.Equal(t, "111111111111", m.Accounts[0].ID)
}

func TestAssemble_JSONSchemaCompliance(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	coverage := NewCoverageTracker()
	coverage.MarkIAMGAAD()

	m, err := Assemble(AssembleInput{
		GAAD:             gaad,
		Resources:        resources,
		Coverage:         coverage,
		PermissionFormat: "policy_summary",
	})
	require.NoError(t, err)

	data, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)

	// Parse back to verify structure
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	// Required fields
	assert.Equal(t, ModelVersion, raw["version"])
	assert.NotNil(t, raw["principals"])
	assert.NotNil(t, raw["permission_source"])
	assert.NotNil(t, raw["goal"])

	// Verify no unexpected top-level keys (additionalProperties: false)
	schemaKeys := map[string]bool{
		"version": true, "collection_coverage": true, "accounts": true,
		"principals": true, "resources": true, "permission_source": true,
		"resource_policies": true, "structural_facts": true, "goal": true, "config": true,
	}
	for key := range raw {
		assert.True(t, schemaKeys[key], "unexpected top-level key %q (additionalProperties: false)", key)
	}

	// Verify principals have required fields
	principals := raw["principals"].([]interface{})
	for _, p := range principals {
		pm := p.(map[string]interface{})
		assert.NotEmpty(t, pm["arn"], "principal must have arn")
		assert.NotEmpty(t, pm["account"], "principal must have account")
		assert.NotEmpty(t, pm["type"], "principal must have type")
	}

	// Verify resources have required fields
	if rawResources, ok := raw["resources"].([]interface{}); ok {
		for _, r := range rawResources {
			rm := r.(map[string]interface{})
			assert.NotEmpty(t, rm["arn"], "resource must have arn")
			assert.NotEmpty(t, rm["type"], "resource must have type")
			assert.NotEmpty(t, rm["account"], "resource must have account")
		}
	}

	// Verify structural facts have required fields
	if rawFacts, ok := raw["structural_facts"].([]interface{}); ok {
		for _, f := range rawFacts {
			fm := f.(map[string]interface{})
			assert.NotEmpty(t, fm["type"], "fact must have type")
			assert.NotEmpty(t, fm["from"], "fact must have from")
			assert.NotEmpty(t, fm["to"], "fact must have to")
		}
	}
}

func TestAssemble_EvaluatedTriplesFormat(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	relationships := store.NewMap[output.AWSIAMRelationship]()
	relationships.Set("key1", output.AWSIAMRelationship{
		Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111111111111:role/Admin"}},
		Resource:  output.AWSResource{ARN: "arn:aws:iam::111111111111:role/LambdaRole"},
		Action:    "sts:AssumeRole",
	})

	m, err := Assemble(AssembleInput{
		GAAD:             gaad,
		Resources:        resources,
		Relationships:    relationships,
		PermissionFormat: "evaluated_triples",
	})
	require.NoError(t, err)

	assert.Equal(t, PermSourceEvaluatedTriples, m.PermissionSource.Type)
	require.Len(t, m.PermissionSource.Triples, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:role/Admin", m.PermissionSource.Triples[0].Principal)
	assert.Equal(t, "sts:AssumeRole", m.PermissionSource.Triples[0].Action)
	assert.True(t, m.PermissionSource.Triples[0].Allowed)
}

func TestAssemble_EvaluatedTriples_NoRelationships(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	m, err := Assemble(AssembleInput{
		GAAD:             gaad,
		Resources:        resources,
		PermissionFormat: "evaluated_triples",
	})
	require.NoError(t, err)

	assert.Equal(t, PermSourceEvaluatedTriples, m.PermissionSource.Type)
	assert.Nil(t, m.PermissionSource.Triples, "should be nil when no relationships")
}

func TestAssemble_DefaultFormat(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	m, err := Assemble(AssembleInput{
		GAAD:      gaad,
		Resources: resources,
	})
	require.NoError(t, err)

	assert.Equal(t, PermSourcePolicySummary, m.PermissionSource.Type)
}

func TestAssemble_EmptyGAAD_ReturnsError(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()

	_, err := Assemble(AssembleInput{
		GAAD:      gaad,
		Resources: resources,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IAM principals")
}

func TestAssemble_PreservesRootTrust(t *testing.T) {
	trustStmt := types.PolicyStatementList{
		{
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: &types.DynaString{"arn:aws:iam::111111111111:root"},
			},
			Action:   &types.DynaString{"sts:AssumeRole"},
			Resource: &types.DynaString{"arn:aws:iam::111111111111:role/Admin"},
		},
	}
	trustPolicy := types.Policy{Statement: &trustStmt}

	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}

	gaad := types.NewAuthorizationAccountDetails("111111111111",
		[]types.UserDetail{
			{Arn: "arn:aws:iam::111111111111:user/Dev", UserName: "Dev"},
		}, nil,
		[]types.RoleDetail{
			{
				Arn:                      "arn:aws:iam::111111111111:role/Admin",
				RoleName:                 "Admin",
				AssumeRolePolicyDocument: trustPolicy,
				RolePolicyList: []types.InlinePolicy{
					{PolicyName: "AdminAccess", PolicyDocument: types.Policy{Statement: &adminStmt}},
				},
			},
		}, nil)
	resources := store.NewMap[output.AWSResource]()

	m, err := Assemble(AssembleInput{GAAD: gaad, Resources: resources})
	require.NoError(t, err)

	// Root trust should be preserved as-is (the solver handles matching)
	found := false
	for _, f := range m.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::111111111111:role/Admin" &&
			f.To == "arn:aws:iam::111111111111:root" {
			found = true
		}
	}
	assert.True(t, found, "Assemble should preserve root trust facts for the solver to interpret")
}

func TestAssemble_SpecificAttacker(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()

	m, err := Assemble(AssembleInput{
		GAAD:     gaad,
		Resources: resources,
		Attacker: "arn:aws:iam::111111111111:user/Dev",
	})
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::111111111111:user/Dev", m.Goal.Attacker)
}
