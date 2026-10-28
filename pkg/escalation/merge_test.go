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
		Version:  "1.0",
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
	assert.Equal(t, "1.0", merged.Version)

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

func TestMergeModels_MergesCoverage(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.CollectionCoverage = &CollectionCoverage{IAMGAAD: true, LambdaExecutionRoles: true}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.CollectionCoverage = &CollectionCoverage{IAMGAAD: true, S3BucketPolicies: true}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	require.NotNil(t, merged.CollectionCoverage)
	assert.True(t, merged.CollectionCoverage.IAMGAAD)
	assert.True(t, merged.CollectionCoverage.LambdaExecutionRoles)
	assert.True(t, merged.CollectionCoverage.S3BucketPolicies)
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
		Version:    "1.0",
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
		Version:    "1.0",
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
		Version:    "1.0",
		Accounts:   []Account{{ID: "111111111111"}},
		Principals: []Principal{{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{Type: PermSourcePolicySummary},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	modelB := &Model{
		Version:    "1.0",
		Accounts:   []Account{{ID: "222222222222"}},
		Principals: []Principal{{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole}},
		PermissionSource: PermissionSource{Type: PermSourceEvaluatedTriples},
		Goal: Goal{Type: GoalReachAdmin, Attacker: "*"},
	}

	_, err := MergeModels([]*Model{modelA, modelB})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission source type")
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

	assert.Equal(t, "1.0", raw["version"])
	principals := raw["principals"].([]interface{})
	assert.Len(t, principals, 2)
}

// ---------------------------------------------------------------------------
// Trust relationship expansion: root trust → per-principal facts
// ---------------------------------------------------------------------------

func TestExpandRootTrustFacts_AccountRootTrust(t *testing.T) {
	// Role in account B trusts arn:aws:iam::111111111111:root
	// Account A has two principals — both should get trust facts
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
		{ARN: "arn:aws:iam::111111111111:user/UserA", Account: "111111111111", Type: PrincipalTypeUser},
		{ARN: "arn:aws:iam::222222222222:role/RoleB", Account: "222222222222", Type: PrincipalTypeRole},
	}

	facts := []StructuralFact{
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:root", Confidence: 1.0},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	// The root trust should be replaced with per-principal trust facts
	// for roles and users in account 111111111111
	roleATrust := false
	userATrust := false
	rootTrustRemoved := true
	for _, f := range expanded {
		if f.Type != FactTrustRelationship {
			continue
		}
		if f.From == "arn:aws:iam::222222222222:role/RoleB" {
			if f.To == "arn:aws:iam::111111111111:role/RoleA" {
				roleATrust = true
			}
			if f.To == "arn:aws:iam::111111111111:user/UserA" {
				userATrust = true
			}
			if f.To == "arn:aws:iam::111111111111:root" {
				rootTrustRemoved = false
			}
		}
	}

	assert.True(t, roleATrust, "should expand root trust to RoleA")
	assert.True(t, userATrust, "should expand root trust to UserA")
	assert.True(t, rootTrustRemoved, "root trust fact should be replaced with expanded facts")
}

func TestExpandRootTrustFacts_NonRootTrustUnchanged(t *testing.T) {
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
	}

	facts := []StructuralFact{
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:role/RoleA", Confidence: 1.0},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	require.Len(t, expanded, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:role/RoleA", expanded[0].To)
}

func TestExpandRootTrustFacts_NoExpansionWhenAccountNotInModel(t *testing.T) {
	// Root trust to account 333 but no principals from 333 in the model
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
	}

	facts := []StructuralFact{
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::333333333333:root", Confidence: 1.0},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	// Root trust to unknown account should be dropped (no principals to expand to)
	for _, f := range expanded {
		if f.Type == FactTrustRelationship {
			assert.NotEqual(t, "arn:aws:iam::333333333333:root", f.To)
		}
	}
}

func TestExpandRootTrustFacts_GroupsSkipped(t *testing.T) {
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
		{ARN: "arn:aws:iam::111111111111:group/Group", Account: "111111111111", Type: PrincipalTypeGroup},
	}

	facts := []StructuralFact{
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:root", Confidence: 1.0},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	for _, f := range expanded {
		if f.Type == FactTrustRelationship {
			assert.NotContains(t, f.To, "group/", "groups cannot assume roles, should not get trust expansion")
		}
	}
}

func TestExpandRootTrustFacts_PreservesNonTrustFacts(t *testing.T) {
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}

	facts := []StructuralFact{
		{Type: FactLambdaExecutionRole, From: "arn:aws:lambda:us-east-1:111111111111:function:F", To: "arn:aws:iam::111111111111:role/R"},
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/B", To: "arn:aws:iam::111111111111:root"},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	hasLambdaFact := false
	for _, f := range expanded {
		if f.Type == FactLambdaExecutionRole {
			hasLambdaFact = true
		}
	}
	assert.True(t, hasLambdaFact, "non-trust facts should be preserved")
}

func TestExpandRootTrustFacts_MultipleRootTrusts(t *testing.T) {
	principals := []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R1", Account: "111111111111", Type: PrincipalTypeRole},
		{ARN: "arn:aws:iam::222222222222:role/R2", Account: "222222222222", Type: PrincipalTypeRole},
	}

	facts := []StructuralFact{
		// Role R2 trusts account 111 root, Role R1 trusts account 222 root
		{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/R2", To: "arn:aws:iam::111111111111:root"},
		{Type: FactTrustRelationship, From: "arn:aws:iam::111111111111:role/R1", To: "arn:aws:iam::222222222222:root"},
	}

	expanded := ExpandRootTrustFacts(facts, principals)

	// R2 trusts R1 (expanded from 111 root), R1 trusts R2 (expanded from 222 root)
	r2TrustsR1 := false
	r1TrustsR2 := false
	for _, f := range expanded {
		if f.Type != FactTrustRelationship {
			continue
		}
		if f.From == "arn:aws:iam::222222222222:role/R2" && f.To == "arn:aws:iam::111111111111:role/R1" {
			r2TrustsR1 = true
		}
		if f.From == "arn:aws:iam::111111111111:role/R1" && f.To == "arn:aws:iam::222222222222:role/R2" {
			r1TrustsR2 = true
		}
	}
	assert.True(t, r2TrustsR1, "R2 should trust R1 after root expansion")
	assert.True(t, r1TrustsR2, "R1 should trust R2 after root expansion")
}

// ---------------------------------------------------------------------------
// Integration: MergeModels + ExpandRootTrustFacts together
// ---------------------------------------------------------------------------

func TestMergeModels_ExpandsRootTrust(t *testing.T) {
	// Account A: RoleA with sts:AssumeRole on account B's RoleB
	// Account B: RoleB trusts arn:aws:iam::111111111111:root (account A root)
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

	// After merge + root trust expansion, RoleB should have a trust fact to RoleA
	found := false
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::222222222222:role/RoleB" &&
			f.To == "arn:aws:iam::111111111111:role/RoleA" {
			found = true
		}
	}
	assert.True(t, found, "after merge, root trust should be expanded: RoleB should trust RoleA")

	// Root trust should be removed
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship && f.To == "arn:aws:iam::111111111111:root" {
			t.Error("root trust fact should be replaced with expanded per-principal facts")
		}
	}
}

func TestMergeModels_Config_TakesFirst(t *testing.T) {
	modelA := accountModel("111111111111", []Principal{
		{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
	}, nil, nil)
	modelA.Config = &SolverConfig{TimeoutSeconds: 120, FindAllPaths: true}

	modelB := accountModel("222222222222", []Principal{
		{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
	}, nil, nil)
	modelB.Config = &SolverConfig{TimeoutSeconds: 60}

	merged, err := MergeModels([]*Model{modelA, modelB})
	require.NoError(t, err)

	require.NotNil(t, merged.Config)
	assert.Equal(t, 120, merged.Config.TimeoutSeconds)
	assert.True(t, merged.Config.FindAllPaths)
}
