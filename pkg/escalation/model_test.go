package escalation

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModel_ImplementsAurelianModel(t *testing.T) {
	var m interface{} = &Model{}
	_, ok := m.(model.AurelianModel)
	assert.True(t, ok, "Model should implement AurelianModel")
}

func TestModel_ImplementsSingleObjectOutput(t *testing.T) {
	var m interface{} = &Model{}
	_, ok := m.(model.SingleObjectOutput)
	assert.True(t, ok, "Model should implement SingleObjectOutput")
}

func TestModel_MarshalJSON_RoundTrip(t *testing.T) {
	m := &Model{
		Version: "1.0",
		CollectionCoverage: &CollectionCoverage{
			IAMGAAD:              true,
			LambdaExecutionRoles: true,
		},
		Accounts: []Account{{ID: "111111111111", OrgPath: []string{"root", "ou-prod"}}},
		Principals: []Principal{
			{ARN: "arn:aws:iam::111111111111:role/Admin", Account: "111111111111", Type: PrincipalTypeRole, IsAdmin: true},
			{ARN: "arn:aws:iam::111111111111:user/Dev", Account: "111111111111", Type: PrincipalTypeUser},
		},
		Resources: []Resource{
			{ARN: "arn:aws:lambda:us-east-1:111111111111:function:MyFunc", Type: ResourceTypeLambdaFunction, Account: "111111111111"},
		},
		PermissionSource: PermissionSource{
			Type: PermSourcePolicySummary,
			Entries: []PolicySummaryEntry{
				{
					Principal: "arn:aws:iam::111111111111:role/Admin",
					EffectiveStatements: []PolicyStatement{
						{Effect: "Allow", Action: "*", Resource: "*", Source: "inline:Admin/AdminAccess"},
					},
				},
			},
		},
		StructuralFacts: []StructuralFact{
			{Type: FactLambdaExecutionRole, From: "arn:aws:lambda:us-east-1:111111111111:function:MyFunc", To: "arn:aws:iam::111111111111:role/LambdaRole"},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "arn:aws:iam::111111111111:user/Dev"},
	}

	data, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)

	// Verify key fields are present in the JSON
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, "1.0", raw["version"])
	assert.NotNil(t, raw["principals"])
	assert.NotNil(t, raw["permission_source"])
	assert.NotNil(t, raw["goal"])
	assert.NotNil(t, raw["structural_facts"])
	assert.NotNil(t, raw["collection_coverage"])

	// Verify permission_source structure
	ps, ok := raw["permission_source"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "policy_summary", ps["type"])

	// Verify principals
	principals, ok := raw["principals"].([]interface{})
	require.True(t, ok)
	assert.Len(t, principals, 2)
}

func TestPermissionSource_MarshalJSON_PolicySummary(t *testing.T) {
	ps := PermissionSource{
		Type: PermSourcePolicySummary,
		Entries: []PolicySummaryEntry{
			{Principal: "arn:aws:iam::111:role/A", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "s3:*", Resource: "*"},
			}},
		},
	}

	data, err := json.Marshal(ps)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "policy_summary", raw["type"])
	entries, ok := raw["entries"].([]interface{})
	require.True(t, ok)
	assert.Len(t, entries, 1)
}

func TestPermissionSource_MarshalJSON_EvaluatedTriples(t *testing.T) {
	ps := PermissionSource{
		Type: PermSourceEvaluatedTriples,
		Triples: []EvaluatedTriple{
			{Principal: "arn:aws:iam::111:role/A", Action: "sts:AssumeRole", Target: "arn:aws:iam::111:role/B", Allowed: true},
		},
	}

	data, err := json.Marshal(ps)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "evaluated_triples", raw["type"])
	entries, ok := raw["entries"].([]interface{})
	require.True(t, ok)
	assert.Len(t, entries, 1)
}

func TestPermissionSource_MarshalJSON_External(t *testing.T) {
	ps := PermissionSource{
		Type:    PermSourceExternal,
		Command: "aurelian evaluate-permission --serve --gaad-dir ./gaad",
	}

	data, err := json.Marshal(ps)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "external", raw["type"])
	assert.Equal(t, "aurelian evaluate-permission --serve --gaad-dir ./gaad", raw["command"])
	assert.Nil(t, raw["entries"])
}
