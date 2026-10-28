package escalation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers: build minimal per-account models for merge tests
// ---------------------------------------------------------------------------

func accountModel(accountID string, principals []Principal, entries []PolicySummaryEntry, facts []StructuralFact) *Model {
	return &Model{
		Version:  ModelVersion,
		Accounts: []Account{{ID: accountID}},
		Principals: principals,
		PermissionSource: PermissionSource{
			Type:    PermSourcePolicySummary,
			Entries: entries,
		},
		StructuralFacts: facts,
		Goal: Goal{
			Type:     GoalReachAdmin,
			Attacker: "*",
		},
	}
}

// ---------------------------------------------------------------------------
// MergeModels: basic merging
// ---------------------------------------------------------------------------

func TestMergeModels_TwoAccounts(t *testing.T) {
	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
			{ARN: "arn:aws:iam::111111111111:user/UserA", Account: "111111111111", Type: PrincipalTypeUser},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::111111111111:role/RoleA", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::222222222222:role/RoleB"},
			}},
			{Principal: "arn:aws:iam::111111111111:user/UserA", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
			}},
		},
		[]StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::111111111111:role/RoleA", To: "arn:aws:iam::111111111111:user/UserA"},
		},
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/RoleB", Account: "222222222222", Type: PrincipalTypeRole, IsAdmin: true},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::222222222222:role/RoleB", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "*", Resource: "*"},
			}},
		},
		[]StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:role/RoleA"},
		},
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	// Accounts: both present
	assert.Len(t, merged.Accounts, 2)
	accountIDs := map[string]bool{}
	for _, a := range merged.Accounts {
		accountIDs[a.ID] = true
	}
	assert.True(t, accountIDs["111111111111"])
	assert.True(t, accountIDs["222222222222"])

	// Principals: all 3 merged
	assert.Len(t, merged.Principals, 3)

	// Permission source entries: all 3 merged
	assert.Equal(t, PermSourcePolicySummary, merged.PermissionSource.Type)
	assert.Len(t, merged.PermissionSource.Entries, 3)

	// Structural facts: both trust relationships
	assert.Len(t, merged.StructuralFacts, 2)

	// Version preserved
	assert.Equal(t, ModelVersion, merged.Version)

	// Goal preserved (wildcard)
	assert.Equal(t, GoalReachAdmin, merged.Goal.Type)
	assert.Equal(t, "*", merged.Goal.Attacker)
}

func TestMergeModels_PreservesResources(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Resources = []Resource{
		{ARN: "arn:aws:lambda:us-east-1:111111111111:function:F1", Type: ResourceTypeLambdaFunction, Account: "111111111111"},
	}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Resources = []Resource{
		{ARN: "arn:aws:s3:::bucket-b", Type: ResourceTypeS3Bucket, Account: "222222222222"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Resources, 2)
}

func TestMergeModels_PreservesResourcePolicies(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::bucket-a", Policy: map[string]any{"Statement": []any{}}},
	}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::bucket-b", Policy: map[string]any{"Statement": []any{}}},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.ResourcePolicies, 2)
}

func TestMergeModels_SingleModel_ResourcePolicyDoesNotAlias(t *testing.T) {
	m := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	m.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::bucket", Policy: map[string]any{"Version": "2012-10-17", "Statement": []any{}}},
	}

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutating the merged policy must not affect the input
	mergedPolicy := merged.ResourcePolicies[0].Policy.(map[string]any)
	mergedPolicy["Version"] = "MUTATED"
	inputPolicy := m.ResourcePolicies[0].Policy.(map[string]any)
	assert.Equal(t, "2012-10-17", inputPolicy["Version"], "merged ResourcePolicy.Policy must not alias input")
}

func TestMergeModels_CoveragePerAccount(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.CollectionCoverage = map[string]*CollectionCoverage{
		"111111111111": {IAMGAAD: true, LambdaExecutionRoles: true},
	}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.CollectionCoverage = map[string]*CollectionCoverage{
		"222222222222": {IAMGAAD: true, S3BucketPolicies: true},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	require.Len(t, merged.CollectionCoverage, 2)
	require.NotNil(t, merged.CollectionCoverage["111111111111"])
	assert.True(t, merged.CollectionCoverage["111111111111"].IAMGAAD)
	assert.True(t, merged.CollectionCoverage["111111111111"].LambdaExecutionRoles)
	assert.False(t, merged.CollectionCoverage["111111111111"].S3BucketPolicies)

	require.NotNil(t, merged.CollectionCoverage["222222222222"])
	assert.True(t, merged.CollectionCoverage["222222222222"].IAMGAAD)
	assert.True(t, merged.CollectionCoverage["222222222222"].S3BucketPolicies)
	assert.False(t, merged.CollectionCoverage["222222222222"].LambdaExecutionRoles)
}

func TestMergeModels_CoverageRepeatedAccount_ORMerged(t *testing.T) {
	// Same account in two models with different coverage flags — should OR-merge.
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R1", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.CollectionCoverage = map[string]*CollectionCoverage{
		"111111111111": {IAMGAAD: true},
	}

	modelB := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R2", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.CollectionCoverage = map[string]*CollectionCoverage{
		"111111111111": {S3BucketPolicies: true},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	require.NotNil(t, merged.CollectionCoverage["111111111111"])
	assert.True(t, merged.CollectionCoverage["111111111111"].IAMGAAD, "first model's IAMGAAD should be preserved")
	assert.True(t, merged.CollectionCoverage["111111111111"].S3BucketPolicies, "second model's S3BucketPolicies should be OR-merged in")
}

func TestMergeModels_CoverageDoesNotAliasInput(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.CollectionCoverage = map[string]*CollectionCoverage{
		"111111111111": {IAMGAAD: true},
	}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	// modelB has nil coverage

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	require.NotNil(t, merged.CollectionCoverage["111111111111"])
	assert.True(t, merged.CollectionCoverage["111111111111"].IAMGAAD)

	// Mutating merged coverage must not affect the input model
	merged.CollectionCoverage["111111111111"].S3BucketPolicies = true
	assert.False(t, modelA.CollectionCoverage["111111111111"].S3BucketPolicies, "merged coverage must not alias input")
}

func TestMergeModels_MergesCollectionErrors(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.CollectionErrors = []CollectionError{
		{Source: "ec2", Error: "AccessDenied"},
	}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.CollectionErrors = []CollectionError{
		{Source: "lambda", Error: "Throttled"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.CollectionErrors, 2)
}

func TestMergeModels_EvaluatedTriplesFormat(t *testing.T) {
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "222222222222"}},
		Principals: []Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::222222222222:role/R", Action: "sts:AssumeRole", Target: "arn:aws:iam::111111111111:role/R", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Equal(t, PermSourceEvaluatedTriples, merged.PermissionSource.Type)
	assert.Len(t, merged.PermissionSource.Triples, 2)
}

// ---------------------------------------------------------------------------
// MergeModels: edge cases
// ---------------------------------------------------------------------------

func TestMergeModels_EmptySlice_ReturnsError(t *testing.T) {
	_, err := MergeModels(nil)
	require.Error(t, err)

	_, err = MergeModels([]*Model{})
	require.Error(t, err)
}

func TestMergeModels_SingleModel_ReturnsCopy(t *testing.T) {
	m := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	assert.Len(t, merged.Accounts, 1)
	assert.Len(t, merged.Principals, 1)
}

func TestMergeModels_MixedPermissionSourceTypes_ReturnsError(t *testing.T) {
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{Type: PermSourcePolicySummary},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "222222222222"}},
		Principals: []Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{Type: PermSourceEvaluatedTriples},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission source type")
}

func TestMergeModels_ExternalPermissionSource_ReturnsError(t *testing.T) {
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{Type: PermSourceExternal, Command: "some-cmd"},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	_, err := MergeModels([]*Model{modelA})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external")
}

func TestMergeModels_DuplicateAccounts_Deduplicated(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R1", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Accounts = []Account{{ID: "111111111111", OrgPath: []string{"root", "ou-prod"}}}

	modelB := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R2", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Accounts = []Account{{ID: "111111111111"}}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Accounts, 1)
	assert.Equal(t, "111111111111", merged.Accounts[0].ID)
	// First-seen OrgPath wins
	assert.Equal(t, []string{"root", "ou-prod"}, merged.Accounts[0].OrgPath)
	// Principals from both are merged
	assert.Len(t, merged.Principals, 2)
}

func TestMergeModels_DuplicatePrincipals_Deduplicated(t *testing.T) {
	// Same principal in two models (shouldn't happen in practice, but be safe)
	p := Principal{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}

	modelA := accountModel("111111111111", []Principal{p}, nil, nil)
	modelB := accountModel("111111111111", []Principal{p}, nil, nil)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Principals, 1)
}

func TestMergeModels_DuplicatePrincipals_DivergentAttributes_KeepsFirst(t *testing.T) {
	pA := Principal{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole, IsAdmin: false}
	pB := Principal{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole, IsAdmin: true}

	modelA := accountModel("111111111111", []Principal{pA}, nil, nil)
	modelB := accountModel("111111111111", []Principal{pB}, nil, nil)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Principals, 1)
	assert.Equal(t, false, merged.Principals[0].IsAdmin, "first-seen wins")
}

func TestMergeModels_JSONSerializable(t *testing.T) {
	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::111111111111:role/R", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "*", Resource: "*"},
			}},
		},
		nil,
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::222222222222:role/R", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "s3:*", Resource: "*"},
			}},
		},
		nil,
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	data, err := json.MarshalIndent(merged, "", "  ")
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, ModelVersion, raw["version"])
	principals := raw["principals"].([]interface{})
	assert.Len(t, principals, 2)
}

// ---------------------------------------------------------------------------
// Integration: MergeModels preserves root trust for solver-side matching
// ---------------------------------------------------------------------------

func TestMergeModels_PreservesRootTrust(t *testing.T) {
	// Account A: RoleA with sts:AssumeRole on account B's RoleB
	// Account B: RoleB trusts arn:aws:iam::111111111111:root (account A root)
	// Root trust should be preserved as-is (the solver handles matching)
	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::111111111111:role/RoleA", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::222222222222:role/RoleB"},
			}},
		},
		nil,
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/RoleB", Account: "222222222222", Type: PrincipalTypeRole, IsAdmin: true},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::222222222222:role/RoleB", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "*", Resource: "*"},
			}},
		},
		[]StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:root", Confidence: 1.0},
		},
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	// Root trust fact should be preserved for the solver to interpret
	found := false
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::222222222222:role/RoleB" &&
			f.To == "arn:aws:iam::111111111111:root" {
			found = true
		}
	}
	assert.True(t, found, "root trust fact should be preserved in merged model for solver-side matching")
}

func TestMergeModels_CrossModelTrustReferences(t *testing.T) {
	// Model A has a trust fact referencing a principal only present in model B.
	// After merge, the trust fact and both principals should be present.
	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::111111111111:role/RoleA", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::222222222222:role/RoleB"},
			}},
		},
		nil,
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/RoleB", Account: "222222222222", Type: PrincipalTypeRole, IsAdmin: true},
		},
		nil,
		[]StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:role/RoleA", Confidence: 1.0},
		},
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	// Both principals present
	arnSet := map[string]bool{}
	for _, p := range merged.Principals {
		arnSet[p.ARN] = true
	}
	assert.True(t, arnSet["arn:aws:iam::111111111111:role/RoleA"], "RoleA from model A should be in merged model")
	assert.True(t, arnSet["arn:aws:iam::222222222222:role/RoleB"], "RoleB from model B should be in merged model")

	// Cross-model trust fact preserved
	found := false
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::222222222222:role/RoleB" &&
			f.To == "arn:aws:iam::111111111111:role/RoleA" {
			found = true
		}
	}
	assert.True(t, found, "cross-model trust fact should be preserved after merge")
}

func TestMergeModels_DuplicateTrustFactsPreserved(t *testing.T) {
	// Two models both have the same trust fact (e.g. both collected the same
	// cross-account role). Merge concatenates without dedup.
	trustFact := StructuralFact{
		Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/Shared",
		To: "arn:aws:iam::111111111111:role/Caller", Confidence: 1.0,
	}

	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/Caller", Account: "111111111111", Type: PrincipalTypeRole},
		}, nil,
		[]StructuralFact{trustFact},
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/Shared", Account: "222222222222", Type: PrincipalTypeRole},
		}, nil,
		[]StructuralFact{trustFact},
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	count := 0
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::222222222222:role/Shared" &&
			f.To == "arn:aws:iam::111111111111:role/Caller" {
			count++
		}
	}
	assert.Equal(t, 2, count, "duplicate trust facts should be preserved (concatenated, not deduped)")
}

func TestMergeModels_Config_Conflicting_ReturnsError(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Config = &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Config = &SolverConfig{TimeoutSeconds: 60}

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config")
}

func TestMergeModels_Config_Same_Succeeds(t *testing.T) {
	cfg := &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true}

	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Config = cfg

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Config = &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	require.NotNil(t, merged.Config)
	assert.Equal(t, 120, merged.Config.TimeoutSeconds)
	assert.True(t, merged.Config.FindAllPaths)
}

func TestMergeModels_Config_BothNil_Succeeds(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	assert.Nil(t, merged.Config)
}

func TestMergeModels_SingleModel_DoesNotAliasSlices(t *testing.T) {
	m := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	m.StructuralFacts = []StructuralFact{{Type: FactTrustRelationship, From: "role/R", To: "arn:aws:iam::111111111111:root"}}

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutating an element in merged slice must not affect the input
	merged.StructuralFacts[0].From = "MUTATED"
	assert.Equal(t, "role/R", m.StructuralFacts[0].From, "input StructuralFacts must not be modified via merged model")
}

func TestMergeModels_ConfigDoesNotAliasInput(t *testing.T) {
	m := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	m.Config = &SolverConfig{TimeoutSeconds: 120}

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutating merged Config must not affect input
	merged.Config.TimeoutSeconds = 999
	assert.Equal(t, 120, m.Config.TimeoutSeconds, "merged Config must not alias input")
}

func TestMergeModels_MultiModel_ConfigDoesNotAliasInput(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Config = &SolverConfig{TimeoutSeconds: 120}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Config = &SolverConfig{TimeoutSeconds: 120}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	merged.Config.TimeoutSeconds = 999
	assert.Equal(t, 120, modelA.Config.TimeoutSeconds, "merged Config must not alias input model")
}

func TestMergeModels_MismatchedVersions_ReturnsError(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Version = "1.0"

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Version = "2.0"

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestMergeModels_DivergentGoal_ReturnsError(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Goal = Goal{Type: GoalReachAdmin, Attacker: "*"}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Goal = Goal{Type: GoalReachAdmin, Attacker: "arn:aws:iam::222222222222:role/Specific"}

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "goal")
}

func TestMergeModels_DuplicateEntries_DeduplicatedByPrincipal(t *testing.T) {
	// Same principal ARN in two models should produce 1 PolicySummaryEntry, not 2.
	entry := PolicySummaryEntry{
		Principal: "arn:aws:iam::111111111111:role/R",
		EffectiveStatements: []PolicyStatement{
			{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		},
	}

	modelA := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		[]PolicySummaryEntry{entry},
		nil,
	)
	modelB := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		[]PolicySummaryEntry{entry},
		nil,
	)

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Principals, 1, "principal deduped")
	assert.Len(t, merged.PermissionSource.Entries, 1, "entries should be deduped by principal ARN")
}

func TestMergeModels_DuplicateTriples_Deduplicated(t *testing.T) {
	// Same (principal, action, target) triple in two models should produce 1 triple, not 2.
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.PermissionSource.Triples, 1, "duplicate triples should be deduped")
}

func TestMergeModels_DuplicateResources_DeduplicatedByARN(t *testing.T) {
	// Same resource ARN in two models (e.g. cross-account S3 bucket) should produce 1 Resource.
	modelA := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelA.Resources = []Resource{
		{ARN: "arn:aws:s3:::shared-bucket", Type: ResourceTypeS3Bucket, Account: "111111111111"},
	}

	modelB := accountModel("222222222222",
		[]Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelB.Resources = []Resource{
		{ARN: "arn:aws:s3:::shared-bucket", Type: ResourceTypeS3Bucket, Account: "222222222222"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.Resources, 1, "duplicate resources should be deduped by ARN")
}

func TestMergeModels_DuplicateResourcePolicies_DeduplicatedByResource(t *testing.T) {
	// Same resource policy ARN in two models should produce 1 ResourcePolicy.
	modelA := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelA.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::shared-bucket", Policy: map[string]any{"Statement": []any{}}},
	}

	modelB := accountModel("222222222222",
		[]Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelB.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::shared-bucket", Policy: map[string]any{"Statement": []any{}}},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.ResourcePolicies, 1, "duplicate resource policies should be deduped by resource ARN")
}

func TestMergeModels_DivergentTriples_BothKept(t *testing.T) {
	// Same (principal, action, target) but different Allowed — must keep both.
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: false},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.PermissionSource.Triples, 2, "divergent Allowed values must keep both triples")
}

func TestMergeModels_DivergentTriples_DifferentConditions_BothKept(t *testing.T) {
	// Same (principal, action, target, allowed) but different Conditions — must keep both.
	modelA := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    ModelVersion,
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{
				{Principal: "arn:aws:iam::111111111111:role/R", Action: "s3:GetObject", Target: "*", Allowed: true,
					Conditions: []Condition{{Key: "aws:SourceIp", Operator: "IpAddress", Values: []string{"10.0.0.0/8"}}}},
			},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	assert.Len(t, merged.PermissionSource.Triples, 2,
		"same tuple with different conditions must keep both triples")
}

func TestMergeModels_DivergentResourceType_Warns(t *testing.T) {
	// Same resource ARN but different Type — should still dedup but this
	// verifies the warning path runs without panic.
	modelA := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelA.Resources = []Resource{
		{ARN: "arn:aws:s3:::shared-bucket", Type: ResourceTypeS3Bucket, Account: "111111111111"},
	}

	modelB := accountModel("222222222222",
		[]Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelB.Resources = []Resource{
		{ARN: "arn:aws:s3:::shared-bucket", Type: ResourceTypeS3Bucket, Account: "222222222222"},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	assert.Len(t, merged.Resources, 1)
	assert.Equal(t, "111111111111", merged.Resources[0].Account, "first-seen wins")
}

func TestMergeModels_SameGoal_Succeeds(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Goal = Goal{Type: GoalReachAdmin, Attacker: "*"}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Goal = Goal{Type: GoalReachAdmin, Attacker: "*"}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	assert.Equal(t, GoalReachAdmin, merged.Goal.Type)
	assert.Equal(t, "*", merged.Goal.Attacker)
}
