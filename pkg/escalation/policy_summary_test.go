package escalation

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectPolicySummary_UserWithManagedAndInline(t *testing.T) {
	gaad := newTestGAAD()
	resources := store.NewMap[output.AWSResource]()

	entries := CollectPolicySummary(PolicySummaryInput{GAAD: gaad, Resources: resources})

	byPrincipal := make(map[string]PolicySummaryEntry)
	for _, e := range entries {
		byPrincipal[e.Principal] = e
	}

	// Dev user should have statements from managed policy (ReadOnly)
	dev, ok := byPrincipal["arn:aws:iam::111111111111:user/Dev"]
	require.True(t, ok)
	require.NotEmpty(t, dev.EffectiveStatements)

	// Check that s3:Get* and s3:List* are present from the managed policy
	actions := make(map[string]bool)
	for _, s := range dev.EffectiveStatements {
		actions[s.Action] = true
	}
	assert.True(t, actions["s3:Get*"], "should have s3:Get*")
	assert.True(t, actions["s3:List*"], "should have s3:List*")
}

func TestCollectPolicySummary_RoleWithInlineAdmin(t *testing.T) {
	gaad := newTestGAAD()
	resources := store.NewMap[output.AWSResource]()

	entries := CollectPolicySummary(PolicySummaryInput{GAAD: gaad, Resources: resources})

	byPrincipal := make(map[string]PolicySummaryEntry)
	for _, e := range entries {
		byPrincipal[e.Principal] = e
	}

	// Admin role should have * : *
	admin, ok := byPrincipal["arn:aws:iam::111111111111:role/Admin"]
	require.True(t, ok)
	require.NotEmpty(t, admin.EffectiveStatements)

	found := false
	for _, s := range admin.EffectiveStatements {
		if s.Effect == "Allow" && s.Action == "*" && s.Resource == "*" {
			found = true
			assert.Contains(t, s.Source, "inline:Admin/AdminAccess")
		}
	}
	assert.True(t, found, "admin role should have Allow *:*")
}

func TestFlattenStatements_NotAction(t *testing.T) {
	stmts := types.PolicyStatementList{
		{
			Effect:    "Deny",
			NotAction: &types.DynaString{"iam:*"},
			Resource:  &types.DynaString{"*"},
		},
	}

	result := flattenStatements(&stmts, "test")
	require.Len(t, result, 1)
	assert.Equal(t, "NotAction:iam:*", result[0].Action)
	assert.Equal(t, "Deny", result[0].Effect)
}

func TestFlattenStatements_NotResource_DenyDropped(t *testing.T) {
	// Deny+NotResource is dropped entirely because the solver cannot model
	// inverse resource matching. Replacing with "*" would over-deny and create
	// false negatives. Dropping the deny under-denies, which is conservative-safe.
	stmts := types.PolicyStatementList{
		{
			Effect:      "Deny",
			Action:      &types.DynaString{"s3:*"},
			NotResource: &types.DynaString{"arn:aws:s3:::my-bucket"},
		},
	}

	result := flattenStatements(&stmts, "test")
	require.Len(t, result, 0, "Deny+NotResource should be dropped entirely")
}

func TestFlattenStatements_NotResource_Allow(t *testing.T) {
	// Allow+NotResource should also be treated as wildcard resource.
	stmts := types.PolicyStatementList{
		{
			Effect:      "Allow",
			Action:      &types.DynaString{"iam:PassRole"},
			NotResource: &types.DynaString{"arn:aws:iam::111111111111:role/restricted"},
		},
	}

	result := flattenStatements(&stmts, "test")
	require.Len(t, result, 1)
	assert.Equal(t, "*", result[0].Resource, "Allow+NotResource should be treated as wildcard")
	assert.Equal(t, "Allow", result[0].Effect)
}

func TestFlattenStatements_NotResource_DenyMultipleDropped(t *testing.T) {
	// Deny with multiple NotResource entries should also be dropped.
	stmts := types.PolicyStatementList{
		{
			Effect:      "Deny",
			Action:      &types.DynaString{"s3:DeleteObject"},
			NotResource: &types.DynaString{"arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*"},
		},
	}

	result := flattenStatements(&stmts, "test")
	require.Len(t, result, 0, "Deny+NotResource should be dropped entirely")
}

func TestFlattenStatements_MultipleActionsAndResources(t *testing.T) {
	stmts := types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &types.DynaString{"s3:GetObject", "s3:PutObject"},
			Resource: &types.DynaString{"arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*"},
		},
	}

	result := flattenStatements(&stmts, "test")
	// 2 actions × 2 resources = 4 statements
	assert.Len(t, result, 4)
}

func TestConvertConditions(t *testing.T) {
	cond := &types.Condition{
		"StringEquals": types.ConditionStatement{
			"aws:RequestedRegion": types.DynaString{"us-east-1", "us-west-2"},
		},
		"IpAddress": types.ConditionStatement{
			"aws:SourceIp": types.DynaString{"10.0.0.0/8"},
		},
	}

	result := convertConditions(cond)
	require.Len(t, result, 2)

	byOp := make(map[string]Condition)
	for _, c := range result {
		byOp[c.Operator] = c
	}

	assert.Equal(t, "aws:RequestedRegion", byOp["StringEquals"].Key)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, byOp["StringEquals"].Values)
	assert.Equal(t, "aws:SourceIp", byOp["IpAddress"].Key)
}

func TestConvertConditions_Nil(t *testing.T) {
	result := convertConditions(nil)
	assert.Nil(t, result)
}

func TestCollectPolicySummary_PrincipalWithNoPolicies(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		[]types.UserDetail{
			{Arn: "arn:aws:iam::111111111111:user/NoPolicies", UserName: "NoPolicies"},
		}, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()

	entries := CollectPolicySummary(PolicySummaryInput{GAAD: gaad, Resources: resources})
	// Principal with no policies should still get an entry (explicit coverage)
	require.Len(t, entries, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:user/NoPolicies", entries[0].Principal)
	assert.Empty(t, entries[0].EffectiveStatements)

	// Spec requires [] not null in JSON
	data, err := json.Marshal(entries[0])
	require.NoError(t, err)
	assert.Contains(t, string(data), `"effective_statements":[]`,
		"empty statements must serialize as [] not null")
}

func TestCollectPolicySummary_ResourcePolicyGrants(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil, nil,
		[]types.RoleDetail{
			{Arn: "arn:aws:iam::111111111111:role/S3Consumer", RoleName: "S3Consumer"},
		}, nil)

	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:s3:::shared-bucket", output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ARN:          "arn:aws:s3:::shared-bucket",
		AccountRef:   "111111111111",
		ResourcePolicy: &types.Policy{
			Statement: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						AWS: &types.DynaString{"arn:aws:iam::111111111111:role/S3Consumer"},
					},
					Action:   &types.DynaString{"s3:GetObject"},
					Resource: &types.DynaString{"arn:aws:s3:::shared-bucket/*"},
				},
			},
		},
	})

	entries := CollectPolicySummary(PolicySummaryInput{GAAD: gaad, Resources: resources})

	byPrincipal := make(map[string]PolicySummaryEntry)
	for _, e := range entries {
		byPrincipal[e.Principal] = e
	}

	// S3Consumer role should get the resource-policy grant even though it has no identity policies
	consumer, ok := byPrincipal["arn:aws:iam::111111111111:role/S3Consumer"]
	require.True(t, ok, "S3Consumer should appear in policy summary from resource policy")

	found := false
	for _, s := range consumer.EffectiveStatements {
		if s.Action == "s3:GetObject" && s.Source == "resource_policy:arn:aws:s3:::shared-bucket" {
			found = true
		}
	}
	assert.True(t, found, "should include s3:GetObject from resource policy")
}

func TestCollectPolicySummary_GroupWithPolicies(t *testing.T) {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	adminPolicy := types.Policy{Statement: &adminStmt}

	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil, // no users
		[]types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111111111111:group/Admins",
				GroupName: "Admins",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "Admin", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"},
				},
			},
		},
		nil, // no roles
		[]types.ManagedPolicyDetail{
			{
				Arn:        "arn:aws:iam::aws:policy/AdministratorAccess",
				PolicyName: "AdministratorAccess",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: adminPolicy},
				},
			},
		},
	)
	resources := store.NewMap[output.AWSResource]()

	entries := CollectPolicySummary(PolicySummaryInput{GAAD: gaad, Resources: resources})

	require.Len(t, entries, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:group/Admins", entries[0].Principal)
	require.NotEmpty(t, entries[0].EffectiveStatements)

	found := false
	for _, s := range entries[0].EffectiveStatements {
		if s.Effect == "Allow" && s.Action == "*" && s.Resource == "*" {
			found = true
		}
	}
	assert.True(t, found, "group should have Allow *:* from managed policy")
}

func TestCollectPolicySummary_SCPIntegration(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil,
		nil,
		[]types.RoleDetail{
			{Arn: "arn:aws:iam::111111111111:role/TestRole", RoleName: "TestRole"},
		},
		nil,
	)

	// Create org policies with an SCP.
	scpStmt := types.PolicyStatementList{
		{Effect: "Deny", Action: &types.DynaString{"s3:DeleteBucket"}, Resource: &types.DynaString{"*"}},
	}
	scpArn := "arn:aws:organizations::111111111111:policy/scp-deny-delete"
	op := &orgpolicies.OrgPolicies{
		SCPs: []orgpolicies.PolicyData{{
			PolicySummary: orgpolicies.PolicySummaryRef{Arn: &scpArn},
			PolicyContent: types.Policy{Statement: &scpStmt},
		}},
		Targets: []orgpolicies.OrgPolicyTarget{{
			Account: &orgpolicies.Account{ID: "111111111111"},
			SCPs:    orgpolicies.OrgPolicyTargetPolicies{DirectPolicies: []string{scpArn}},
		}},
	}
	resources := store.NewMap[output.AWSResource]()

	entries := CollectPolicySummary(PolicySummaryInput{
		GAAD:        gaad,
		OrgPolicies: op,
		Resources:   resources,
	})

	require.Len(t, entries, 1)
	found := false
	for _, s := range entries[0].EffectiveStatements {
		if s.Effect == "Deny" && s.Action == "s3:DeleteBucket" && s.Source == "scp" {
			found = true
		}
	}
	assert.True(t, found, "should include SCP deny statement with scp source")
}
