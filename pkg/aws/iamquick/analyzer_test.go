package iamquick

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ----------------------------------------------------------------

func ds(vals ...string) *types.DynaString {
	d := types.DynaString(vals)
	return &d
}

func stmts(ss ...types.PolicyStatement) *types.PolicyStatementList {
	l := types.PolicyStatementList(ss)
	return &l
}

func allowActions(actions ...string) types.PolicyStatement {
	return types.PolicyStatement{Effect: "Allow", Action: ds(actions...), Resource: ds("*")}
}

func denyActions(actions ...string) types.PolicyStatement {
	return types.PolicyStatement{Effect: "Deny", Action: ds(actions...), Resource: ds("*")}
}

func allowNotActions(actions ...string) types.PolicyStatement {
	return types.PolicyStatement{Effect: "Allow", NotAction: ds(actions...), Resource: ds("*")}
}

func denyNotActions(actions ...string) types.PolicyStatement {
	return types.PolicyStatement{Effect: "Deny", NotAction: ds(actions...), Resource: ds("*")}
}

func inlinePolicy(name string, ss ...types.PolicyStatement) types.InlinePolicy {
	return types.InlinePolicy{
		PolicyName:     name,
		PolicyDocument: types.Policy{Statement: stmts(ss...)},
	}
}

func collectFindings(gaad *types.AuthorizationAccountDetails) []output.AWSResource {
	a := NewAnalyzer(gaad)
	out := pipeline.New[model.AurelianModel]()
	go func() {
		a.Analyze(out)
		out.Close()
	}()
	var results []output.AWSResource
	for m := range out.Range() {
		if r, ok := m.(output.AWSResource); ok {
			results = append(results, r)
		}
	}
	return results
}

func findingsByType(findings []output.AWSResource, findingType string) []output.AWSResource {
	var out []output.AWSResource
	for _, f := range findings {
		if f.Properties["finding_type"] == findingType {
			out = append(out, f)
		}
	}
	return out
}

func privescByName(findings []output.AWSResource, name string) []output.AWSResource {
	var out []output.AWSResource
	for _, f := range findings {
		if f.Properties["finding_type"] == "privesc" && f.Properties["privesc_type"] == name {
			out = append(out, f)
		}
	}
	return out
}

func trustsByType(findings []output.AWSResource, trustType string) []output.AWSResource {
	var out []output.AWSResource
	for _, f := range findings {
		if f.Properties["finding_type"] == "trust" && f.Properties["trust_type"] == trustType {
			out = append(out, f)
		}
	}
	return out
}

// --- isActionAllowed --------------------------------------------------------

func TestIsActionAllowed(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		allowed []actionGroup
		denied  []actionGroup
		want    bool
	}{
		{
			name:    "exact match allowed",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"sts:AssumeRole"}}},
			want:    true,
		},
		{
			name:    "wildcard match allowed",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"sts:*"}}},
			want:    true,
		},
		{
			name:    "no match",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"ec2:RunInstances"}}},
			want:    false,
		},
		{
			name:    "explicit deny overrides allow",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"sts:AssumeRole"}}},
			denied:  []actionGroup{{patterns: []string{"sts:AssumeRole"}}},
			want:    false,
		},
		{
			name:    "NotAction allow grants unlisted action",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"ec2:RunInstances"}, notAction: true}},
			want:    true,
		},
		{
			name:    "NotAction allow does not grant listed action",
			target:  "ec2:RunInstances",
			allowed: []actionGroup{{patterns: []string{"ec2:RunInstances"}, notAction: true}},
			want:    false,
		},
		{
			name:    "NotAction deny blocks unlisted action",
			target:  "sts:AssumeRole",
			allowed: []actionGroup{{patterns: []string{"sts:AssumeRole"}}},
			denied:  []actionGroup{{patterns: []string{"ec2:RunInstances"}, notAction: true}},
			want:    false,
		},
		{
			name:    "NotAction deny does not block listed action",
			target:  "ec2:RunInstances",
			allowed: []actionGroup{{patterns: []string{"ec2:RunInstances"}}},
			denied:  []actionGroup{{patterns: []string{"ec2:RunInstances"}, notAction: true}},
			want:    true,
		},
		// --- deny wildcard vs allow wildcard ---
		{
			name:   "deny wildcard blocks allow wildcard",
			target: "sts:AssumeRole",
			allowed: []actionGroup{
				{patterns: []string{"sts:*"}},
			},
			denied: []actionGroup{
				{patterns: []string{"sts:AssumeRole"}},
			},
			want: false,
		},
		{
			name:   "deny service wildcard blocks specific allow",
			target: "iam:PassRole",
			allowed: []actionGroup{
				{patterns: []string{"iam:*"}},
			},
			denied: []actionGroup{
				{patterns: []string{"iam:PassRole"}},
			},
			want: false,
		},
		{
			name:   "service wildcard does not cross service boundary",
			target: "ec2:RunInstances",
			allowed: []actionGroup{
				{patterns: []string{"iam:*"}},
			},
			want: false,
		},
		// --- NotAction with multiple patterns ---
		{
			name:   "NotAction allow with multiple excluded actions grants other actions",
			target: "iam:PassRole",
			allowed: []actionGroup{
				{patterns: []string{"s3:*", "ec2:TerminateInstances"}, notAction: true},
			},
			want: true,
		},
		{
			name:   "NotAction allow with multiple excluded actions blocks wildcard-matched action",
			target: "s3:GetObject",
			allowed: []actionGroup{
				{patterns: []string{"s3:*", "ec2:TerminateInstances"}, notAction: true},
			},
			want: false,
		},
		// --- NotAction Deny combined with Allow ---
		{
			name:   "NotAction deny everything-except-s3 blocks non-s3 allow",
			target: "codebuild:StartBuild",
			allowed: []actionGroup{
				{patterns: []string{"codebuild:StartBuild"}},
			},
			denied: []actionGroup{
				{patterns: []string{"s3:*"}, notAction: true},
			},
			want: false,
		},
		{
			name:   "NotAction deny everything-except-s3 allows s3 action",
			target: "s3:GetObject",
			allowed: []actionGroup{
				{patterns: []string{"s3:GetObject"}},
			},
			denied: []actionGroup{
				{patterns: []string{"s3:*"}, notAction: true},
			},
			want: true,
		},
		// --- Multiple overlapping allow/deny groups ---
		{
			name:   "multiple allows one deny on different action still allows target",
			target: "sts:AssumeRole",
			allowed: []actionGroup{
				{patterns: []string{"sts:*"}},
				{patterns: []string{"sts:AssumeRole"}},
				{patterns: []string{"iam:PassRole"}},
			},
			denied: []actionGroup{
				{patterns: []string{"iam:PassRole"}},
			},
			want: true,
		},
		{
			name:   "action prefix wildcard does not match different suffix",
			target: "s3:PutObject",
			allowed: []actionGroup{
				{patterns: []string{"s3:Get*"}},
			},
			want: false,
		},
		{
			name:   "action prefix wildcard matches correct suffix",
			target: "s3:GetObject",
			allowed: []actionGroup{
				{patterns: []string{"s3:Get*"}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isActionAllowed(tt.target, tt.allowed, tt.denied)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- hasAllActions ----------------------------------------------------------

func TestHasAllActions(t *testing.T) {
	allowed := []actionGroup{
		{patterns: []string{"iam:PassRole"}},
		{patterns: []string{"lambda:CreateFunction"}},
		{patterns: []string{"lambda:InvokeFunction"}},
	}

	assert.True(t, hasAllActions(
		[]string{"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"},
		allowed, nil,
	), "all three actions present")

	assert.False(t, hasAllActions(
		[]string{"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"},
		allowed[:2], nil, // missing InvokeFunction
	), "missing one action")
}

// --- collectActions ---------------------------------------------------------

func TestCollectActions(t *testing.T) {
	policies := []types.Policy{
		{Statement: stmts(
			allowActions("s3:GetObject", "s3:PutObject"),
			denyActions("s3:DeleteObject"),
		)},
		{Statement: stmts(
			allowNotActions("ec2:TerminateInstances"),
		)},
	}

	allowed, denied := collectActions(policies)

	// Two Action allows + one NotAction allow
	assert.Len(t, allowed, 3)
	assert.Len(t, denied, 1)

	// Verify the NotAction group
	var foundNotAction bool
	for _, a := range allowed {
		if a.notAction {
			foundNotAction = true
			assert.Equal(t, []string{"ec2:TerminateInstances"}, a.patterns)
		}
	}
	assert.True(t, foundNotAction)
}

// --- privesc scanning (end-to-end) ------------------------------------------

func TestScanPrivescs_UserWithLambdaCreate(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/privesc-user",
			UserName: "privesc-user",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("privesc", allowActions(
					"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole",
				)),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	privescs := findingsByType(findings, "privesc")
	lambdaCreate := privescByName(findings, "lambda-create")

	require.NotEmpty(t, privescs, "should detect at least one privesc")
	require.Len(t, lambdaCreate, 1, "should detect lambda-create privesc")
	assert.Equal(t, "arn:aws:iam::123456789012:user/privesc-user", lambdaCreate[0].ARN)
	assert.Equal(t, "AWS::IAM::User", lambdaCreate[0].ResourceType)
}

func TestScanPrivescs_RoleWithStsAssume(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/overprivileged",
			RoleName: "overprivileged",
			RolePolicyList: []types.InlinePolicy{
				inlinePolicy("inline", allowActions("sts:AssumeRole")),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	stsAssume := privescByName(findings, "sts-assume")

	require.Len(t, stsAssume, 1)
	assert.Equal(t, "AWS::IAM::Role", stsAssume[0].ResourceType)
}

func TestScanPrivescs_DenyBlocksPrivesc(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/denied-user",
			UserName: "denied-user",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("allow", allowActions("sts:AssumeRole")),
				inlinePolicy("deny", denyActions("sts:AssumeRole")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	stsAssume := privescByName(findings, "sts-assume")
	assert.Empty(t, stsAssume, "deny should block the privesc")
}

func TestScanPrivescs_WildcardAllowMatchesPrivesc(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/admin",
			UserName: "admin",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("admin", allowActions("*")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	privescs := findingsByType(findings, "privesc")

	// A wildcard allow should match every privesc combo in the list.
	assert.Equal(t, len(privescCombinations), len(privescs),
		"wildcard allow should trigger all %d privesc combos", len(privescCombinations))

	// Verify specific high-value combos are present.
	for _, name := range []string{"sts-assume", "lambda-create", "ec2-passrole", "ssm-send-command", "iam-create-login"} {
		found := privescByName(findings, name)
		assert.Len(t, found, 1, "wildcard allow should detect %s", name)
	}
}

func TestScanPrivescs_ManagedPolicyResolved(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/managed-user",
			UserName: "managed-user",
			AttachedManagedPolicies: []types.ManagedPolicy{
				{PolicyArn: "arn:aws:iam::123456789012:policy/custom"},
			},
		}},
		nil, nil,
		[]types.ManagedPolicyDetail{{
			Arn:              "arn:aws:iam::123456789012:policy/custom",
			DefaultVersionId: "v1",
			PolicyVersionList: []types.PolicyVersion{{
				VersionId:        "v1",
				IsDefaultVersion: true,
				Document: types.Policy{
					Statement: stmts(allowActions("codebuild:StartBuild")),
				},
			}},
		}},
	)

	findings := collectFindings(gaad)
	cb := privescByName(findings, "codebuild-existing")
	require.Len(t, cb, 1, "managed policy should be resolved and trigger codebuild-existing privesc")
}

func TestScanPrivescs_GroupPolicyInherited(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:       "arn:aws:iam::123456789012:user/group-member",
			UserName:  "group-member",
			GroupList: []string{"dev-group"},
		}},
		[]types.GroupDetail{{
			Arn:       "arn:aws:iam::123456789012:group/dev-group",
			GroupName: "dev-group",
			GroupPolicyList: []types.InlinePolicy{
				inlinePolicy("group-policy", allowActions("ssm:SendCommand")),
			},
		}},
		nil, nil,
	)

	findings := collectFindings(gaad)
	ssm := privescByName(findings, "ssm-send-command")
	require.Len(t, ssm, 1, "user should inherit group policy and trigger ssm-send-command privesc")
	assert.Equal(t, "arn:aws:iam::123456789012:user/group-member", ssm[0].ARN)
}

func TestScanPrivescs_DenyWildcardBlocksSpecificAllows(t *testing.T) {
	// User has the exact lambda-create actions, but iam:* is denied.
	// iam:PassRole falls under iam:* deny, so lambda-create should not trigger.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/partial-denied",
			UserName: "partial-denied",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("allow", allowActions(
					"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole",
				)),
				inlinePolicy("deny-iam", denyActions("iam:*")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	lambdaCreate := privescByName(findings, "lambda-create")
	assert.Empty(t, lambdaCreate, "iam:* deny should block iam:PassRole, preventing lambda-create privesc")
}

func TestScanPrivescs_ServiceWildcardAllowMatchesCombo(t *testing.T) {
	// User has iam:* (service wildcard) — should match all IAM-only combos.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/iam-admin",
			UserName: "iam-admin",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("iam-admin", allowActions("iam:*")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)

	// iam:* should match IAM-only combos.
	for _, name := range []string{
		"iam-create-login", "iam-update-login", "iam-add-to-group",
		"iam-group-put-policy", "iam-group-attach-policy",
	} {
		found := privescByName(findings, name)
		assert.Len(t, found, 1, "iam:* should detect %s", name)
	}

	// iam:* should NOT match combos requiring non-IAM actions.
	lambdaCreate := privescByName(findings, "lambda-create")
	assert.Empty(t, lambdaCreate, "iam:* should not match lambda-create (needs lambda:CreateFunction)")
}

func TestScanPrivescs_CombinedInlineGroupManagedPolicy(t *testing.T) {
	// Privesc combo lambda-create requires: lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole
	// These come from three different sources:
	//   - inline policy: lambda:CreateFunction
	//   - group policy: lambda:InvokeFunction
	//   - managed policy: iam:PassRole
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/combo-user",
			UserName: "combo-user",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("inline", allowActions("lambda:CreateFunction")),
			},
			AttachedManagedPolicies: []types.ManagedPolicy{
				{PolicyArn: "arn:aws:iam::123456789012:policy/passrole"},
			},
			GroupList: []string{"lambda-invoke-group"},
		}},
		[]types.GroupDetail{{
			Arn:       "arn:aws:iam::123456789012:group/lambda-invoke-group",
			GroupName: "lambda-invoke-group",
			GroupPolicyList: []types.InlinePolicy{
				inlinePolicy("group-inline", allowActions("lambda:InvokeFunction")),
			},
		}},
		nil,
		[]types.ManagedPolicyDetail{{
			Arn:              "arn:aws:iam::123456789012:policy/passrole",
			DefaultVersionId: "v1",
			PolicyVersionList: []types.PolicyVersion{{
				VersionId:        "v1",
				IsDefaultVersion: true,
				Document: types.Policy{
					Statement: stmts(allowActions("iam:PassRole")),
				},
			}},
		}},
	)

	findings := collectFindings(gaad)
	lambdaCreate := privescByName(findings, "lambda-create")
	require.Len(t, lambdaCreate, 1, "inline+group+managed should combine to form lambda-create privesc")
	assert.Equal(t, "arn:aws:iam::123456789012:user/combo-user", lambdaCreate[0].ARN)
}

func TestScanPrivescs_NotActionDenyBlocksCombo(t *testing.T) {
	// NotAction Deny: ["s3:*"] means "deny everything except s3".
	// This should block sts:AssumeRole even though it's explicitly allowed.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/notaction-denied",
			UserName: "notaction-denied",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("allow", allowActions("sts:AssumeRole")),
				inlinePolicy("deny-everything-except-s3", denyNotActions("s3:*")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	stsAssume := privescByName(findings, "sts-assume")
	assert.Empty(t, stsAssume, "NotAction deny of everything-except-s3 should block sts:AssumeRole")
}

func TestScanPrivescs_NotActionAllowGrantsCombo(t *testing.T) {
	// NotAction Allow: ["s3:*"] means "allow everything except s3".
	// This should allow sts:AssumeRole (it's not s3).
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/notaction-allowed",
			UserName: "notaction-allowed",
			UserPolicyList: []types.InlinePolicy{
				inlinePolicy("allow-all-except-s3", allowNotActions("s3:*")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	stsAssume := privescByName(findings, "sts-assume")
	require.Len(t, stsAssume, 1, "NotAction allow excluding only s3 should grant sts:AssumeRole")
}

func TestScanPrivescs_NilStatementPolicy(t *testing.T) {
	// A policy with nil Statement should be safely skipped.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/nil-stmt",
			UserName: "nil-stmt",
			UserPolicyList: []types.InlinePolicy{
				{PolicyName: "empty", PolicyDocument: types.Policy{Statement: nil}},
				inlinePolicy("real", allowActions("ssm:StartSession")),
			},
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	ssm := privescByName(findings, "ssm-start-session")
	require.Len(t, ssm, 1, "nil statement policy should be skipped without breaking other policy evaluation")
}

func TestScanPrivescs_CrossAccountGroupIgnored(t *testing.T) {
	// User in account A is member of group with matching name in account B.
	// Cross-account group policies should NOT be inherited.
	gaad := types.NewAuthorizationAccountDetails("multi-account",
		[]types.UserDetail{{
			Arn:       "arn:aws:iam::111111111111:user/cross-acct",
			UserName:  "cross-acct",
			GroupList: []string{"shared-group"},
		}},
		[]types.GroupDetail{{
			Arn:       "arn:aws:iam::222222222222:group/shared-group",
			GroupName: "shared-group",
			GroupPolicyList: []types.InlinePolicy{
				inlinePolicy("group-policy", allowActions("ssm:SendCommand")),
			},
		}},
		nil, nil,
	)

	findings := collectFindings(gaad)
	privescs := findingsByType(findings, "privesc")
	assert.Empty(t, privescs, "cross-account group policy should not be inherited")
}

func TestScanPrivescs_NoPolicies(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		[]types.UserDetail{{
			Arn:      "arn:aws:iam::123456789012:user/empty",
			UserName: "empty",
		}},
		nil, nil, nil,
	)

	findings := collectFindings(gaad)
	privescs := findingsByType(findings, "privesc")
	assert.Empty(t, privescs)
}

// --- trust analysis ---------------------------------------------------------

func TestTrusts_RootTrust(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/cross-account",
			RoleName: "cross-account",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:    "Allow",
					Principal: &types.Principal{AWS: ds("arn:aws:iam::999999999999:root")},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	rootTrusts := trustsByType(findings, "root-trust")

	require.Len(t, rootTrusts, 1)
	assert.Equal(t, "999999999999", rootTrusts[0].Properties["trusted"])
	assert.Equal(t, "None", rootTrusts[0].Properties["conditions"])
}

func TestTrusts_RootTrustViaNotPrincipal(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/notprincipal-role",
			RoleName: "notprincipal-role",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:       "Allow",
					NotPrincipal: &types.Principal{AWS: ds("arn:aws:iam::123456789012:user/specific-user")},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	rootTrusts := trustsByType(findings, "root-trust")

	require.Len(t, rootTrusts, 1, "root not excluded in NotPrincipal should produce root-trust")
	assert.Equal(t, "Any Account (via NotPrincipal)", rootTrusts[0].Properties["trusted"])
}

func TestTrusts_ServiceTrust(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/lambda-role",
			RoleName: "lambda-role",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:    "Allow",
					Principal: &types.Principal{Service: ds("lambda.amazonaws.com")},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	serviceTrusts := trustsByType(findings, "service-trust")

	require.Len(t, serviceTrusts, 1)
	assert.Equal(t, "lambda", serviceTrusts[0].Properties["trusted"])
}

func TestTrusts_FederatedTrust(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/sso-role",
			RoleName: "sso-role",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:    "Allow",
					Principal: &types.Principal{Federated: ds("arn:aws:iam::123456789012:saml-provider/MyIDP")},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	fedTrusts := trustsByType(findings, "federated-trust")

	require.Len(t, fedTrusts, 1)
	assert.Equal(t, "arn:aws:iam::123456789012:saml-provider/MyIDP", fedTrusts[0].Properties["trusted"])
}

func TestTrusts_PrincipalTrust(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/delegated",
			RoleName: "delegated",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:    "Allow",
					Principal: &types.Principal{AWS: ds("arn:aws:iam::123456789012:role/admin-role")},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	principalTrusts := trustsByType(findings, "principal-trust:IAM Role")

	require.Len(t, principalTrusts, 1)
	assert.Equal(t, "arn:aws:iam::123456789012:role/admin-role", principalTrusts[0].Properties["trusted"])
}

func TestTrusts_MultiStatementTrustPolicy(t *testing.T) {
	// A single role with two Allow statements: root trust + service trust.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/multi-trust",
			RoleName: "multi-trust",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(
					types.PolicyStatement{
						Effect:    "Allow",
						Principal: &types.Principal{AWS: ds("arn:aws:iam::999999999999:root")},
					},
					types.PolicyStatement{
						Effect:    "Allow",
						Principal: &types.Principal{Service: ds("lambda.amazonaws.com")},
					},
				),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	rootTrusts := trustsByType(findings, "root-trust")
	serviceTrusts := trustsByType(findings, "service-trust")

	assert.Len(t, rootTrusts, 1, "should emit root-trust from first statement")
	assert.Len(t, serviceTrusts, 1, "should emit service-trust from second statement")
}

func TestTrusts_DenyStatementIgnored(t *testing.T) {
	// A Deny statement in the trust policy should be skipped entirely.
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/deny-in-trust",
			RoleName: "deny-in-trust",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(
					types.PolicyStatement{
						Effect:    "Deny",
						Principal: &types.Principal{AWS: ds("arn:aws:iam::999999999999:root")},
					},
					types.PolicyStatement{
						Effect:    "Allow",
						Principal: &types.Principal{Service: ds("ec2.amazonaws.com")},
					},
				),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	rootTrusts := trustsByType(findings, "root-trust")
	serviceTrusts := trustsByType(findings, "service-trust")

	assert.Empty(t, rootTrusts, "Deny statement should not produce root-trust finding")
	assert.Len(t, serviceTrusts, 1, "Allow statement should still produce service-trust")
}

func TestTrusts_ConditionsFormatted(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/conditional-trust",
			RoleName: "conditional-trust",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect:    "Allow",
					Principal: &types.Principal{AWS: ds("arn:aws:iam::999999999999:root")},
					Condition: &types.Condition{
						"StringEquals": {
							"sts:ExternalId": []string{"my-secret-id"},
						},
					},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	rootTrusts := trustsByType(findings, "root-trust")

	require.Len(t, rootTrusts, 1)
	conditions := rootTrusts[0].Properties["conditions"].(string)
	assert.NotEqual(t, "None", conditions, "conditions should be formatted, not None")
	assert.Contains(t, conditions, "ExternalId", "conditions should reference ExternalId")
}

func TestTrusts_NotPrincipalImplicitAccess(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("123456789012",
		nil, nil,
		[]types.RoleDetail{{
			Arn:      "arn:aws:iam::123456789012:role/open-role",
			RoleName: "open-role",
			AssumeRolePolicyDocument: types.Policy{
				Statement: stmts(types.PolicyStatement{
					Effect: "Allow",
					NotPrincipal: &types.Principal{AWS: ds(
						"arn:aws:iam::123456789012:user/specific-user",
					)},
				}),
			},
		}},
		nil,
	)

	findings := collectFindings(gaad)
	notPrincipal := trustsByType(findings, "principal-trust:NotPrincipal")

	// root not excluded, users wildcard not excluded, roles wildcard not excluded
	require.Len(t, notPrincipal, 3, "should produce 3 implicit access findings: root, user/*, role/*")

	var trustedValues []string
	for _, f := range notPrincipal {
		trustedValues = append(trustedValues, f.Properties["trusted"].(string))
	}
	assert.Contains(t, trustedValues, "*:root")
	assert.Contains(t, trustedValues, "*:user/*")
	assert.Contains(t, trustedValues, "*:role/*")
}

// --- helper functions -------------------------------------------------------

func TestIsRootPrincipal(t *testing.T) {
	assert.True(t, isRootPrincipal("arn:aws:iam::123456789012:root"))
	assert.True(t, isRootPrincipal("123456789012:root"))
	assert.False(t, isRootPrincipal("arn:aws:iam::123456789012:user/admin"))
	assert.False(t, isRootPrincipal("arn:aws:iam::123456789012:role/test"))
}

func TestExtractAccountID(t *testing.T) {
	assert.Equal(t, "123456789012", extractAccountID("arn:aws:iam::123456789012:user/admin"))
	assert.Equal(t, "999999999999", extractAccountID("arn:aws:iam::999999999999:role/test"))
	assert.Equal(t, "", extractAccountID("short"))
}

func TestGetPrincipalType(t *testing.T) {
	assert.Equal(t, "IAM User", getPrincipalType("arn:aws:iam::123456789012:user/admin"))
	assert.Equal(t, "IAM Role", getPrincipalType("arn:aws:iam::123456789012:role/test"))
	assert.Equal(t, "IAM Group", getPrincipalType("arn:aws:iam::123456789012:group/devs"))
	assert.Equal(t, "", getPrincipalType("arn:aws:iam::123456789012:root"))
	assert.Equal(t, "", getPrincipalType("not-an-arn"))
}

func TestCleanServiceName(t *testing.T) {
	assert.Equal(t, "lambda", cleanServiceName("lambda.amazonaws.com"))
	assert.Equal(t, "ec2", cleanServiceName("ec2.amazonaws.com"))
	assert.Equal(t, "vpce", cleanServiceName("vpce.us-east-1.vpce.amazonaws.com"))
	assert.Equal(t, "lambda", cleanServiceName("lambda"))
}

func TestAnalyzePotentialAccess(t *testing.T) {
	t.Run("specific user excluded leaves all wildcards open", func(t *testing.T) {
		result := analyzePotentialAccess(types.DynaString{"arn:aws:iam::123456789012:user/someone"})
		assert.Contains(t, result, "*:root")
		assert.Contains(t, result, "*:user/*")
		assert.Contains(t, result, "*:role/*")
		assert.Len(t, result, 3)
	})

	t.Run("root excluded", func(t *testing.T) {
		result := analyzePotentialAccess(types.DynaString{"arn:aws:iam::123456789012:root"})
		assert.NotContains(t, result, "*:root")
		assert.Contains(t, result, "*:user/*")
		assert.Contains(t, result, "*:role/*")
		assert.Len(t, result, 2)
	})

	t.Run("user wildcard excluded", func(t *testing.T) {
		result := analyzePotentialAccess(types.DynaString{"arn:aws:iam::123456789012:user/*"})
		assert.Contains(t, result, "*:root")
		assert.NotContains(t, result, "*:user/*")
		assert.Contains(t, result, "*:role/*")
	})

	t.Run("role wildcard excluded", func(t *testing.T) {
		result := analyzePotentialAccess(types.DynaString{"arn:aws:iam::123456789012:role/*"})
		assert.Contains(t, result, "*:root")
		assert.Contains(t, result, "*:user/*")
		assert.NotContains(t, result, "*:role/*")
	})

	t.Run("all three excluded yields empty", func(t *testing.T) {
		result := analyzePotentialAccess(types.DynaString{
			"arn:aws:iam::123456789012:root",
			"arn:aws:iam::123456789012:user/*",
			"arn:aws:iam::123456789012:role/*",
		})
		assert.Empty(t, result)
	})
}
