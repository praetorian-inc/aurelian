package escalation

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	// For each bool field on CollectionCoverage, verify that OR-merge works:
	// model A sets only that field, model B sets none → merged has it true.
	// This uses reflection so new fields are automatically covered.
	covType := reflect.TypeOf(CollectionCoverage{})
	for i := 0; i < covType.NumField(); i++ {
		f := covType.Field(i)
		if f.Type.Kind() != reflect.Bool {
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			modelA := accountModel("111111111111", []Principal{
				{ARN: "arn:aws:iam::111111111111:role/R1", Account: "111111111111", Type: PrincipalTypeRole},
			}, nil, nil)
			covA := &CollectionCoverage{}
			reflect.ValueOf(covA).Elem().Field(i).SetBool(true)
			modelA.CollectionCoverage = map[string]*CollectionCoverage{"111111111111": covA}

			modelB := accountModel("111111111111", []Principal{
				{ARN: "arn:aws:iam::111111111111:role/R2", Account: "111111111111", Type: PrincipalTypeRole},
			}, nil, nil)
			modelB.CollectionCoverage = map[string]*CollectionCoverage{
				"111111111111": {},
			}

			merged, err := MergeModels([]*Model{modelA, modelB})
			require.NoError(t, err)

			require.NotNil(t, merged.CollectionCoverage["111111111111"])
			got := reflect.ValueOf(merged.CollectionCoverage["111111111111"]).Elem().Field(i).Bool()
			assert.True(t, got, "%s should be OR-merged from model A", f.Name)
		})
	}
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
	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Version = "99.0"

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same version")
	assert.Contains(t, err.Error(), "99.0")
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

func TestMergeModels_SingleModel_EntriesDoNotAlias(t *testing.T) {
	m := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	m.PermissionSource.Entries = []PolicySummaryEntry{{
		Principal: "arn:aws:iam::111111111111:role/R",
		EffectiveStatements: []PolicyStatement{
			{Effect: "Allow", Action: "sts:AssumeRole", Resource: "*"},
		},
	}}

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutating a nested statement in the merged model must not affect input.
	merged.PermissionSource.Entries[0].EffectiveStatements[0].Action = "MUTATED"
	assert.Equal(t, "sts:AssumeRole", m.PermissionSource.Entries[0].EffectiveStatements[0].Action,
		"merged EffectiveStatements must not alias input")
}

func TestMergeModels_SingleModel_TriplesDoNotAlias(t *testing.T) {
	m := &Model{
		Version:  ModelVersion,
		Accounts: []Account{{ID: "111111111111"}},
		Principals: []Principal{
			{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
		},
		PermissionSource: PermissionSource{
			Type: PermSourceEvaluatedTriples,
			Triples: []EvaluatedTriple{{
				Principal:  "arn:aws:iam::111111111111:role/R",
				Action:     "sts:AssumeRole",
				Target:     "*",
				Allowed:    true,
				Conditions: []Condition{{Operator: "StringEquals", Key: "k", Values: []string{"v"}}},
			}},
		},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutating nested Conditions in merged model must not affect input.
	merged.PermissionSource.Triples[0].Conditions[0].Key = "MUTATED"
	assert.Equal(t, "k", m.PermissionSource.Triples[0].Conditions[0].Key,
		"merged Triple Conditions must not alias input")
}

func TestMergeModels_MultiModel_ResourcePolicyDoesNotAlias(t *testing.T) {
	modelA := accountModel("111111111111",
		[]Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelA.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::bucket-a", Policy: map[string]any{"Version": "2012-10-17"}},
	}

	modelB := accountModel("222222222222",
		[]Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		nil, nil,
	)
	modelB.ResourcePolicies = []ResourcePolicy{
		{Resource: "arn:aws:s3:::bucket-b", Policy: map[string]any{"Version": "2012-10-17"}},
	}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	require.Len(t, merged.ResourcePolicies, 2)

	// Mutating the merged model's policy must not affect input.
	merged.ResourcePolicies[0].Policy.(map[string]any)["Version"] = "MUTATED"
	assert.Equal(t, "2012-10-17", modelA.ResourcePolicies[0].Policy.(map[string]any)["Version"],
		"multi-model merge must deep-copy ResourcePolicy.Policy")
}

func TestMergeModels_UnsupportedVersion_ReturnsError(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Version = "99.0"

	_, err := MergeModels([]*Model{modelA})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
	assert.Contains(t, err.Error(), ModelVersion)
}

func TestMergeModels_MultiModel_EntriesDoNotAlias(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.PermissionSource.Entries = []PolicySummaryEntry{{
		Principal:           "arn:aws:iam::111111111111:role/R",
		EffectiveStatements: []PolicyStatement{{Effect: "Allow", Action: "s3:GetObject", Resource: "*"}},
	}}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.PermissionSource.Entries = []PolicySummaryEntry{{
		Principal:           "arn:aws:iam::222222222222:role/R",
		EffectiveStatements: []PolicyStatement{{Effect: "Allow", Action: "iam:PassRole", Resource: "*"}},
	}}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)
	require.Len(t, merged.PermissionSource.Entries, 2)

	merged.PermissionSource.Entries[0].EffectiveStatements[0].Action = "MUTATED"
	assert.Equal(t, "s3:GetObject", modelA.PermissionSource.Entries[0].EffectiveStatements[0].Action,
		"multi-model merge must deep-copy EffectiveStatements")
}

// ---------------------------------------------------------------------------
// Merge correctness oracle: merge then re-serialize must be stable
// ---------------------------------------------------------------------------

func TestMergeModels_Idempotent(t *testing.T) {
	// Merging a model with itself should produce a result that, when
	// serialized, is identical to merging the original once.
	m := richModel()
	merged1, err := MergeModels([]*Model{m})
	require.NoError(t, err)
	merged2, err := MergeModels([]*Model{merged1})
	require.NoError(t, err)

	j1, _ := json.Marshal(merged1)
	j2, _ := json.Marshal(merged2)
	assert.JSONEq(t, string(j1), string(j2), "merge should be idempotent on single model")
}

func TestMergeModels_NoInputAliasing(t *testing.T) {
	// After merging, mutating every mutable field in the merged model
	// must not affect the inputs. This is the generic aliasing oracle.
	m := richModel()
	origJSON, _ := json.Marshal(m)

	merged, err := MergeModels([]*Model{m})
	require.NoError(t, err)

	// Mutate every slice/pointer field we can reach in merged.
	if len(merged.Accounts) > 0 {
		merged.Accounts[0].ID = "MUTATED"
		if len(merged.Accounts[0].OrgPath) > 0 {
			merged.Accounts[0].OrgPath[0] = "MUTATED"
		}
	}
	if len(merged.Principals) > 0 {
		merged.Principals[0].ARN = "MUTATED"
	}
	if len(merged.Resources) > 0 {
		merged.Resources[0].ARN = "MUTATED"
	}
	if len(merged.StructuralFacts) > 0 {
		merged.StructuralFacts[0].From = "MUTATED"
	}
	if len(merged.ResourcePolicies) > 0 {
		merged.ResourcePolicies[0].Resource = "MUTATED"
	}
	if len(merged.CollectionErrors) > 0 {
		merged.CollectionErrors[0].Error = "MUTATED"
		if len(merged.CollectionErrors[0].Regions) > 0 {
			merged.CollectionErrors[0].Regions[0] = "MUTATED"
		}
	}
	if len(merged.PermissionSource.Entries) > 0 {
		merged.PermissionSource.Entries[0].Principal = "MUTATED"
		if len(merged.PermissionSource.Entries[0].EffectiveStatements) > 0 {
			merged.PermissionSource.Entries[0].EffectiveStatements[0].Action = "MUTATED"
		}
	}
	if merged.Config != nil {
		merged.Config.TimeoutSeconds = 999999
	}

	afterJSON, _ := json.Marshal(m)
	assert.JSONEq(t, string(origJSON), string(afterJSON),
		"mutating merged model must not affect input")
}

// richModel builds a model with data in every field for aliasing/correctness tests.
func richModel() *Model {
	return &Model{
		Version:  ModelVersion,
		Accounts: []Account{{ID: "111", OrgPath: []string{"org", "ou"}}},
		Principals: []Principal{
			{ARN: "arn:aws:iam::111:role/R", Account: "111", Type: PrincipalTypeRole},
		},
		Resources: []Resource{
			{ARN: "arn:aws:s3:::bucket", Type: "s3_bucket", Account: "111"},
		},
		StructuralFacts: []StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::111:role/R", To: "arn:aws:iam::111:root"},
		},
		ResourcePolicies: []ResourcePolicy{
			{Resource: "arn:aws:s3:::bucket", Policy: map[string]any{"Version": "2012-10-17", "Statement": []any{}}},
		},
		CollectionErrors: []CollectionError{
			{Source: "s3", Error: "access denied", Regions: []string{"us-east-1", "us-west-2"}},
		},
		PermissionSource: PermissionSource{
			Type: PermSourcePolicySummary,
			Entries: []PolicySummaryEntry{{
				Principal: "arn:aws:iam::111:role/R",
				EffectiveStatements: []PolicyStatement{
					{Effect: "Allow", Action: "s3:GetObject", Resource: "*",
						Conditions: []Condition{{Operator: "StringEquals", Key: "k", Values: []string{"v1", "v2"}}}},
				},
			}},
		},
		CollectionCoverage: map[string]*CollectionCoverage{
			"111": {IAMGAAD: true, S3BucketPolicies: true},
		},
		Config: &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true},
		Goal:   Goal{Type: GoalReachAdmin, Attacker: "*"},
	}
}

func TestMergeModels_LargeScale_Correctness(t *testing.T) {
	const (
		numAccounts       = 5
		principalsPerAcct = 100
		stmtsPerPrincipal = 20
		resourcesPerAcct  = 30
		factsPerAcct      = 50
	)

	models := make([]*Model, numAccounts)
	for i := 0; i < numAccounts; i++ {
		acct := fmt.Sprintf("%012d", i+1)
		models[i] = buildLargeModel(acct, principalsPerAcct, stmtsPerPrincipal, resourcesPerAcct, factsPerAcct)
	}

	merged, err := MergeModels(models)
	require.NoError(t, err)

	// Accounts: each model contributes 1 unique account.
	assert.Len(t, merged.Accounts, numAccounts, "each account should appear once")

	// Principals: each account has unique ARNs, so total = sum.
	assert.Len(t, merged.Principals, numAccounts*principalsPerAcct,
		"all principals from all accounts should be present")

	// Resources: each account has unique ARNs, so total = sum.
	assert.Len(t, merged.Resources, numAccounts*resourcesPerAcct,
		"all resources from all accounts should be present")

	// ResourcePolicies: one per resource, unique ARNs.
	assert.Len(t, merged.ResourcePolicies, numAccounts*resourcesPerAcct,
		"all resource policies should be present")

	// StructuralFacts: not deduped, so total = sum.
	assert.Len(t, merged.StructuralFacts, numAccounts*factsPerAcct,
		"all structural facts should be present")

	// Entries: each account has unique principal ARNs, so total = sum.
	assert.Len(t, merged.PermissionSource.Entries, numAccounts*principalsPerAcct,
		"all permission entries should be present")

	// CollectionErrors: 1 per model, not deduped.
	assert.Len(t, merged.CollectionErrors, numAccounts,
		"all collection errors should be present")

	// Coverage: one key per account, all should be present.
	assert.Len(t, merged.CollectionCoverage, numAccounts,
		"coverage should have one entry per account")

	// Spot-check: verify specific entries survived.
	for i := 0; i < numAccounts; i++ {
		acct := fmt.Sprintf("%012d", i+1)

		// Account exists.
		found := false
		for _, a := range merged.Accounts {
			if a.ID == acct {
				found = true
				assert.Equal(t, []string{"org", "ou-prod"}, a.OrgPath, "OrgPath should be preserved")
			}
		}
		assert.True(t, found, "account %s should be in merged output", acct)

		// First principal's first statement survived with conditions.
		firstARN := fmt.Sprintf("arn:aws:iam::%s:role/Role0", acct)
		var entry *PolicySummaryEntry
		for j := range merged.PermissionSource.Entries {
			if merged.PermissionSource.Entries[j].Principal == firstARN {
				entry = &merged.PermissionSource.Entries[j]
				break
			}
		}
		if assert.NotNil(t, entry, "entry for %s should exist", firstARN) {
			assert.Len(t, entry.EffectiveStatements, stmtsPerPrincipal,
				"all statements for %s should be present", firstARN)
			assert.Len(t, entry.EffectiveStatements[0].Conditions, 1,
				"conditions should be preserved")
			assert.Len(t, entry.EffectiveStatements[0].Conditions[0].Values, 2,
				"condition values should be preserved")
		}

		// Coverage preserved.
		cov, ok := merged.CollectionCoverage[acct]
		assert.True(t, ok, "coverage for %s should exist", acct)
		if ok {
			assert.True(t, cov.IAMGAAD)
			assert.True(t, cov.S3BucketPolicies)
			assert.True(t, cov.LambdaExecutionRoles)
		}
	}

	// Verify no aliasing: mutate merged, check inputs unchanged.
	origFirst, _ := json.Marshal(models[0])
	merged.Principals[0].ARN = "MUTATED"
	merged.PermissionSource.Entries[0].EffectiveStatements[0].Action = "MUTATED"
	if len(merged.ResourcePolicies) > 0 {
		merged.ResourcePolicies[0].Resource = "MUTATED"
	}
	afterFirst, _ := json.Marshal(models[0])
	assert.JSONEq(t, string(origFirst), string(afterFirst),
		"mutating merged output must not affect input models")
}

// ---------------------------------------------------------------------------
// Benchmark: merge performance at scale
// ---------------------------------------------------------------------------

func buildLargeModel(acct string, nPrincipals, nStmtsPerPrincipal, nResources, nFacts int) *Model {
	principals := make([]Principal, nPrincipals)
	entries := make([]PolicySummaryEntry, nPrincipals)
	for i := 0; i < nPrincipals; i++ {
		arn := fmt.Sprintf("arn:aws:iam::%s:role/Role%d", acct, i)
		principals[i] = Principal{ARN: arn, Account: acct, Type: PrincipalTypeRole}
		stmts := make([]PolicyStatement, nStmtsPerPrincipal)
		for j := 0; j < nStmtsPerPrincipal; j++ {
			stmts[j] = PolicyStatement{
				Effect:   "Allow",
				Action:   fmt.Sprintf("svc%d:Action%d", j%20, j),
				Resource: fmt.Sprintf("arn:aws:s3:::%s-bucket-%d/*", acct, j%50),
				Conditions: []Condition{
					{Operator: "StringEquals", Key: "aws:RequestedRegion", Values: []string{"us-east-1", "us-west-2"}},
				},
			}
		}
		entries[i] = PolicySummaryEntry{Principal: arn, EffectiveStatements: stmts}
	}

	resources := make([]Resource, nResources)
	resourcePolicies := make([]ResourcePolicy, nResources)
	for i := 0; i < nResources; i++ {
		rArn := fmt.Sprintf("arn:aws:s3:::%s-bucket-%d", acct, i)
		resources[i] = Resource{ARN: rArn, Type: "s3_bucket", Account: acct}
		resourcePolicies[i] = ResourcePolicy{
			Resource: rArn,
			Policy:   map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": rArn + "/*"}}},
		}
	}

	facts := make([]StructuralFact, nFacts)
	for i := 0; i < nFacts; i++ {
		facts[i] = StructuralFact{
			Type:       FactTrustRelationship,
			From:       fmt.Sprintf("arn:aws:iam::%s:role/Role%d", acct, i%nPrincipals),
			To:         fmt.Sprintf("arn:aws:iam::%s:root", acct),
			Confidence: 1.0,
		}
	}

	return &Model{
		Version:          ModelVersion,
		Accounts:         []Account{{ID: acct, OrgPath: []string{"org", "ou-prod"}}},
		Principals:       principals,
		Resources:        resources,
		ResourcePolicies: resourcePolicies,
		StructuralFacts:  facts,
		CollectionErrors: []CollectionError{
			{Source: "s3_bucket_policies", Error: "partial: 3 buckets denied", Regions: []string{"us-east-1", "eu-west-1"}},
		},
		PermissionSource: PermissionSource{
			Type:    PermSourcePolicySummary,
			Entries: entries,
		},
		CollectionCoverage: map[string]*CollectionCoverage{
			acct: {IAMGAAD: true, S3BucketPolicies: true, LambdaExecutionRoles: true},
		},
		Config: &SolverConfig{TimeoutSeconds: 300, FindAllPaths: true},
		Goal:   Goal{Type: GoalReachAdmin, Attacker: "*"},
	}
}

func BenchmarkMergeModels_10Accounts_5kPrincipals(b *testing.B) {
	const (
		numAccounts    = 10
		principalsPerAcct = 5000
		stmtsPerPrincipal = 50
		resourcesPerAcct  = 200
		factsPerAcct      = 500
	)
	models := make([]*Model, numAccounts)
	for i := 0; i < numAccounts; i++ {
		acct := fmt.Sprintf("%012d", i+1)
		models[i] = buildLargeModel(acct, principalsPerAcct, stmtsPerPrincipal, resourcesPerAcct, factsPerAcct)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := MergeModels(models)
		if err != nil {
			b.Fatal(err)
		}
	}
}
