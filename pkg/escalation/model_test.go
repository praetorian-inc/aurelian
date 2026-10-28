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
		Version: ModelVersion,
		CollectionCoverage: map[string]*CollectionCoverage{
			"111111111111": {
				IAMGAAD:              true,
				LambdaExecutionRoles: true,
			},
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

	assert.Equal(t, ModelVersion, raw["version"])
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

// ---------------------------------------------------------------------------
// UnmarshalJSON: round-trip deserialization
// ---------------------------------------------------------------------------

func TestPermissionSource_UnmarshalJSON_PolicySummary(t *testing.T) {
	original := PermissionSource{
		Type: PermSourcePolicySummary,
		Entries: []PolicySummaryEntry{
			{Principal: "arn:aws:iam::111:role/A", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "s3:*", Resource: "*", Source: "inline:A/policy"},
			}},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PermissionSource
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, PermSourcePolicySummary, decoded.Type)
	require.Len(t, decoded.Entries, 1)
	assert.Equal(t, "arn:aws:iam::111:role/A", decoded.Entries[0].Principal)
	require.Len(t, decoded.Entries[0].EffectiveStatements, 1)
	assert.Equal(t, "s3:*", decoded.Entries[0].EffectiveStatements[0].Action)
}

func TestPermissionSource_UnmarshalJSON_EvaluatedTriples(t *testing.T) {
	original := PermissionSource{
		Type: PermSourceEvaluatedTriples,
		Triples: []EvaluatedTriple{
			{Principal: "arn:aws:iam::111:role/A", Action: "sts:AssumeRole", Target: "arn:aws:iam::111:role/B", Allowed: true},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PermissionSource
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, PermSourceEvaluatedTriples, decoded.Type)
	require.Len(t, decoded.Triples, 1)
	assert.Equal(t, "arn:aws:iam::111:role/A", decoded.Triples[0].Principal)
	assert.Equal(t, "sts:AssumeRole", decoded.Triples[0].Action)
	assert.True(t, decoded.Triples[0].Allowed)
}

func TestPermissionSource_UnmarshalJSON_External(t *testing.T) {
	original := PermissionSource{
		Type:    PermSourceExternal,
		Command: "aurelian evaluate-permission --serve",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PermissionSource
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, PermSourceExternal, decoded.Type)
	assert.Equal(t, "aurelian evaluate-permission --serve", decoded.Command)
}

func TestModel_FullRoundTrip_PolicySummary(t *testing.T) {
	original := &Model{
		Version: ModelVersion,
		CollectionCoverage: map[string]*CollectionCoverage{
			"111111111111": {
				IAMGAAD:              true,
				LambdaExecutionRoles: true,
				S3BucketPolicies:     true,
			},
		},
		CollectionErrors: []CollectionError{
			{Source: "ec2", Error: "AccessDenied", Regions: []string{"us-east-1"}},
		},
		Accounts: []Account{{ID: "111111111111", OrgPath: []string{"root", "ou-prod"}}},
		Principals: []Principal{
			{ARN: "arn:aws:iam::111111111111:role/Admin", Account: "111111111111", Type: PrincipalTypeRole, IsAdmin: true},
			{ARN: "arn:aws:iam::111111111111:user/Dev", Account: "111111111111", Type: PrincipalTypeUser},
		},
		Resources: []Resource{
			{ARN: "arn:aws:lambda:us-east-1:111111111111:function:F1", Type: ResourceTypeLambdaFunction, Account: "111111111111"},
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
			{Type: FactLambdaExecutionRole, From: "arn:aws:lambda:us-east-1:111111111111:function:F1", To: "arn:aws:iam::111111111111:role/LambdaRole", Confidence: 1.0},
			{Type: FactTrustRelationship, From: "arn:aws:iam::111111111111:role/Admin", To: "arn:aws:iam::111111111111:user/Dev", Confidence: 1.0},
		},
		Goal:   Goal{Type: GoalReachAdmin, Attacker: "*"},
		Config: &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true},
	}

	data, err := json.MarshalIndent(original, "", "  ")
	require.NoError(t, err)

	var decoded Model
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Version, decoded.Version)
	require.NotNil(t, decoded.CollectionCoverage["111111111111"])
	assert.Equal(t, original.CollectionCoverage["111111111111"].IAMGAAD, decoded.CollectionCoverage["111111111111"].IAMGAAD)
	assert.Equal(t, original.CollectionCoverage["111111111111"].LambdaExecutionRoles, decoded.CollectionCoverage["111111111111"].LambdaExecutionRoles)
	assert.Equal(t, original.CollectionCoverage["111111111111"].S3BucketPolicies, decoded.CollectionCoverage["111111111111"].S3BucketPolicies)
	require.Len(t, decoded.CollectionErrors, 1)
	assert.Equal(t, "ec2", decoded.CollectionErrors[0].Source)
	require.Len(t, decoded.Accounts, 1)
	assert.Equal(t, "111111111111", decoded.Accounts[0].ID)
	assert.Equal(t, []string{"root", "ou-prod"}, decoded.Accounts[0].OrgPath)
	require.Len(t, decoded.Principals, 2)
	assert.Equal(t, PrincipalTypeRole, decoded.Principals[0].Type)
	assert.True(t, decoded.Principals[0].IsAdmin)
	require.Len(t, decoded.Resources, 1)
	assert.Equal(t, ResourceTypeLambdaFunction, decoded.Resources[0].Type)
	assert.Equal(t, PermSourcePolicySummary, decoded.PermissionSource.Type)
	require.Len(t, decoded.PermissionSource.Entries, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:role/Admin", decoded.PermissionSource.Entries[0].Principal)
	require.Len(t, decoded.StructuralFacts, 2)
	assert.Equal(t, FactLambdaExecutionRole, decoded.StructuralFacts[0].Type)
	assert.Equal(t, FactTrustRelationship, decoded.StructuralFacts[1].Type)
	assert.Equal(t, GoalReachAdmin, decoded.Goal.Type)
	assert.Equal(t, "*", decoded.Goal.Attacker)
	require.NotNil(t, decoded.Config)
	assert.Equal(t, 120, decoded.Config.TimeoutSeconds)
	assert.True(t, decoded.Config.FindAllPaths)
}

func TestModel_FullRoundTrip_EvaluatedTriples(t *testing.T) {
	original := &Model{
		Version: ModelVersion,
		Accounts: []Account{{ID: "111111111111"}},
		Principals: []Principal{
			{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
		},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Model
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, PermSourceEvaluatedTriples, decoded.PermissionSource.Type)
	require.Len(t, decoded.PermissionSource.Triples, 1)
	assert.Equal(t, "s3:GetObject", decoded.PermissionSource.Triples[0].Action)
}

func TestPermissionSource_UnmarshalJSON_UnknownType(t *testing.T) {
	data := []byte(`{"type":"bogus","entries":[]}`)
	var ps PermissionSource
	err := json.Unmarshal(data, &ps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestPermissionSource_UnmarshalJSON_WithConditions(t *testing.T) {
	original := PermissionSource{
		Type: PermSourcePolicySummary,
		Entries: []PolicySummaryEntry{
			{Principal: "arn:aws:iam::111:role/A", EffectiveStatements: []PolicyStatement{
				{
					Effect:   "Allow",
					Action:   "s3:GetObject",
					Resource: "arn:aws:s3:::bucket/*",
					Conditions: []Condition{
						{Key: "aws:RequestedRegion", Operator: "StringEquals", Values: []string{"us-east-1"}},
					},
				},
			}},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PermissionSource
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.Len(t, decoded.Entries[0].EffectiveStatements[0].Conditions, 1)
	assert.Equal(t, "aws:RequestedRegion", decoded.Entries[0].EffectiveStatements[0].Conditions[0].Key)
	assert.Equal(t, "StringEquals", decoded.Entries[0].EffectiveStatements[0].Conditions[0].Operator)
	assert.Equal(t, []string{"us-east-1"}, decoded.Entries[0].EffectiveStatements[0].Conditions[0].Values)
}
