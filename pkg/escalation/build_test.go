package escalation

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGAAD() *types.AuthorizationAccountDetails {
	adminStmt := types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &types.DynaString{"*"},
			Resource: &types.DynaString{"*"},
		},
	}
	adminPolicy := types.Policy{Statement: &adminStmt}

	readOnlyStmt := types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &types.DynaString{"s3:Get*", "s3:List*"},
			Resource: &types.DynaString{"arn:aws:s3:::my-bucket/*"},
		},
	}
	readOnlyPolicy := types.Policy{Statement: &readOnlyStmt}

	trustStmt := types.PolicyStatementList{
		{
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: &types.DynaString{"arn:aws:iam::111111111111:user/Dev"},
			},
			Action:   &types.DynaString{"sts:AssumeRole"},
			Resource: &types.DynaString{"arn:aws:iam::111111111111:role/Admin"},
		},
	}
	trustPolicy := types.Policy{Statement: &trustStmt}

	return types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/Dev",
				UserName: "Dev",
				GroupList: []string{"Developers"},
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "ReadOnly", PolicyArn: "arn:aws:iam::111111111111:policy/ReadOnly"},
				},
			},
		},
		[]types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111111111111:group/Developers",
				GroupName: "Developers",
			},
			{
				Arn:       "arn:aws:iam::111111111111:group/Admin",
				GroupName: "Admin",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "AdministratorAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"},
				},
			},
		},
		[]types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111111111111:role/Admin",
				RoleName: "Admin",
				RolePolicyList: []types.InlinePolicy{
					{PolicyName: "AdminAccess", PolicyDocument: adminPolicy},
				},
				AssumeRolePolicyDocument: trustPolicy,
				InstanceProfileList: []types.InstanceProfile{
					{
						Arn:                 "arn:aws:iam::111111111111:instance-profile/AdminIP",
						InstanceProfileName: "AdminIP",
						Roles: []types.InstanceProfileRole{
							{Arn: "arn:aws:iam::111111111111:role/Admin", RoleName: "Admin"},
						},
					},
				},
			},
			{
				Arn:      "arn:aws:iam::111111111111:role/LambdaRole",
				RoleName: "LambdaRole",
			},
		},
		[]types.ManagedPolicyDetail{
			{
				Arn:        "arn:aws:iam::111111111111:policy/ReadOnly",
				PolicyName: "ReadOnly",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: readOnlyPolicy},
				},
			},
			{
				Arn:        "arn:aws:iam::aws:policy/AdministratorAccess",
				PolicyName: "AdministratorAccess",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: adminPolicy},
				},
			},
		},
	)
}

func newTestResources() store.Map[output.AWSResource] {
	m := store.NewMap[output.AWSResource]()
	m.Set("arn:aws:lambda:us-east-1:111111111111:function:MyFunc", output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ARN:          "arn:aws:lambda:us-east-1:111111111111:function:MyFunc",
		AccountRef:   "111111111111",
		Properties:   map[string]any{"Role": "arn:aws:iam::111111111111:role/LambdaRole"},
	})
	m.Set("arn:aws:ec2:us-east-1:111111111111:instance/i-1234", output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ARN:          "arn:aws:ec2:us-east-1:111111111111:instance/i-1234",
		AccountRef:   "111111111111",
		Properties:   map[string]any{"IamInstanceProfile": "arn:aws:iam::111111111111:instance-profile/AdminIP"},
	})
	m.Set("arn:aws:s3:::my-bucket", output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ARN:          "arn:aws:s3:::my-bucket",
		AccountRef:   "111111111111",
		ResourcePolicy: &types.Policy{
			Statement: &types.PolicyStatementList{
				{Effect: "Allow", Action: &types.DynaString{"s3:GetObject"}, Resource: &types.DynaString{"arn:aws:s3:::my-bucket/*"}},
			},
		},
	})
	// IAM resources should be skipped (no solver type mapping)
	m.Set("arn:aws:iam::111111111111:role/SomeRole", output.AWSResource{
		ResourceType: "AWS::IAM::Role",
		ARN:          "arn:aws:iam::111111111111:role/SomeRole",
		AccountRef:   "111111111111",
	})
	return m
}

// ---------------------------------------------------------------------------
// Principals (A.2)
// ---------------------------------------------------------------------------

func TestCollectPrincipals(t *testing.T) {
	gaad := newTestGAAD()
	principals := CollectPrincipals(gaad)

	require.GreaterOrEqual(t, len(principals), 4) // 1 user + 2 roles + 2 groups

	byARN := make(map[string]Principal)
	for _, p := range principals {
		byARN[p.ARN] = p
	}

	// Admin role should be is_admin=true
	admin, ok := byARN["arn:aws:iam::111111111111:role/Admin"]
	require.True(t, ok)
	assert.Equal(t, PrincipalTypeRole, admin.Type)
	assert.True(t, admin.IsAdmin)
	assert.Equal(t, "111111111111", admin.Account)

	// Dev user should be is_admin=false (only has read-only)
	dev, ok := byARN["arn:aws:iam::111111111111:user/Dev"]
	require.True(t, ok)
	assert.Equal(t, PrincipalTypeUser, dev.Type)
	assert.False(t, dev.IsAdmin)

	// Developers group: no policies → is_admin=false
	devGroup, ok := byARN["arn:aws:iam::111111111111:group/Developers"]
	require.True(t, ok)
	assert.Equal(t, PrincipalTypeGroup, devGroup.Type)
	assert.False(t, devGroup.IsAdmin)

	// Admin group: attached AdministratorAccess → is_admin=true
	adminGroup, ok := byARN["arn:aws:iam::111111111111:group/Admin"]
	require.True(t, ok)
	assert.Equal(t, PrincipalTypeGroup, adminGroup.Type)
	assert.True(t, adminGroup.IsAdmin, "group with AdministratorAccess should be is_admin=true")
}

func TestIsAdmin_WithDeny(t *testing.T) {
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
		{Effect: "Deny", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	assert.False(t, isAdmin(stmts), "should not be admin with Deny *:* on *")
}

func TestIsAdmin_WithCondition(t *testing.T) {
	cond := types.Condition{"StringEquals": types.ConditionStatement{"aws:RequestedRegion": types.DynaString{"us-east-1"}}}
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}, Condition: &cond},
	}
	assert.False(t, isAdmin(stmts), "should not be admin with conditions")
}

func TestIsAdmin_True(t *testing.T) {
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	assert.True(t, isAdmin(stmts))
}

// ---------------------------------------------------------------------------
// Resources (A.3)
// ---------------------------------------------------------------------------

func TestCollectResources(t *testing.T) {
	resources := newTestResources()
	result := CollectResources(resources)

	// Should include Lambda, EC2, S3 but NOT IAM::Role
	byARN := make(map[string]Resource)
	for _, r := range result {
		byARN[r.ARN] = r
	}

	assert.Contains(t, byARN, "arn:aws:lambda:us-east-1:111111111111:function:MyFunc")
	assert.Equal(t, ResourceTypeLambdaFunction, byARN["arn:aws:lambda:us-east-1:111111111111:function:MyFunc"].Type)

	assert.Contains(t, byARN, "arn:aws:ec2:us-east-1:111111111111:instance/i-1234")
	assert.Equal(t, ResourceTypeEC2Instance, byARN["arn:aws:ec2:us-east-1:111111111111:instance/i-1234"].Type)

	assert.Contains(t, byARN, "arn:aws:s3:::my-bucket")
	assert.Equal(t, ResourceTypeS3Bucket, byARN["arn:aws:s3:::my-bucket"].Type)

	assert.NotContains(t, byARN, "arn:aws:iam::111111111111:role/SomeRole")
}

// ---------------------------------------------------------------------------
// Structural Facts (A.4)
// ---------------------------------------------------------------------------

func TestCollectStructuralFacts(t *testing.T) {
	gaad := newTestGAAD()
	resources := newTestResources()
	facts := CollectStructuralFacts(gaad, resources)

	types := make(map[StructuralFactType][]StructuralFact)
	for _, f := range facts {
		types[f.Type] = append(types[f.Type], f)
	}

	// Group membership: Dev -> Developers group
	require.Contains(t, types, FactGroupMembership)
	assert.Len(t, types[FactGroupMembership], 1)
	assert.Equal(t, "arn:aws:iam::111111111111:user/Dev", types[FactGroupMembership][0].From)
	assert.Equal(t, "arn:aws:iam::111111111111:group/Developers", types[FactGroupMembership][0].To)

	// Trust relationship: Admin role trusted by Dev user
	require.Contains(t, types, FactTrustRelationship)
	found := false
	for _, f := range types[FactTrustRelationship] {
		if f.From == "arn:aws:iam::111111111111:role/Admin" && f.To == "arn:aws:iam::111111111111:user/Dev" {
			found = true
		}
	}
	assert.True(t, found, "should find trust relationship from Admin role to Dev user")

	// Instance profile: EC2 instance → Admin role (resolved through instance profile)
	require.Contains(t, types, FactInstanceProfile)
	found = false
	for _, f := range types[FactInstanceProfile] {
		if f.From == "arn:aws:ec2:us-east-1:111111111111:instance/i-1234" &&
			f.To == "arn:aws:iam::111111111111:role/Admin" {
			found = true
		}
	}
	assert.True(t, found, "should find instance_profile from EC2 instance to role")

	// Lambda execution role: MyFunc -> LambdaRole
	require.Contains(t, types, FactLambdaExecutionRole)
	found = false
	for _, f := range types[FactLambdaExecutionRole] {
		if f.From == "arn:aws:lambda:us-east-1:111111111111:function:MyFunc" &&
			f.To == "arn:aws:iam::111111111111:role/LambdaRole" {
			found = true
		}
	}
	assert.True(t, found, "should find lambda execution role from MyFunc to LambdaRole")
}

func TestCollectStructuralFacts_CustomerManagedPolicyAttachment(t *testing.T) {
	gaad := newTestGAAD()
	facts := CollectStructuralFacts(gaad, store.NewMap[output.AWSResource]())

	found := false
	for _, f := range facts {
		if f.Type == FactPolicyAttachment &&
			f.From == "arn:aws:iam::111111111111:policy/ReadOnly" &&
			f.To == "arn:aws:iam::111111111111:user/Dev" {
			found = true
			break
		}
	}
	assert.True(t, found, "customer-managed ReadOnly attachment on Dev should emit policy_attachment from policy ARN to user ARN")
}

func TestCollectStructuralFacts_AWSManagedPolicyAttachmentNotEmitted(t *testing.T) {
	gaad := newTestGAAD()
	facts := CollectStructuralFacts(gaad, store.NewMap[output.AWSResource]())

	awsManaged := "arn:aws:iam::aws:policy/AdministratorAccess"
	adminGroup := "arn:aws:iam::111111111111:group/Admin"
	for _, f := range facts {
		if f.Type != FactPolicyAttachment {
			continue
		}
		assert.NotEqual(t, awsManaged, f.From, "AWS-managed AdministratorAccess must not be emitted as policy_attachment From")
		assert.NotEqual(t, awsManaged, f.To, "AWS-managed AdministratorAccess must not be emitted as policy_attachment To")
		assert.False(t, f.From == awsManaged && f.To == adminGroup,
			"AWS-managed AdministratorAccess on Admin group must not be emitted")
	}
}

func TestCollectStructuralFacts_EmptyPolicyArnSkipped(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/NoArn",
				UserName: "NoArn",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "Orphan", PolicyArn: ""},
				},
			},
		}, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()

	facts := CollectStructuralFacts(gaad, resources)
	for _, f := range facts {
		if f.Type == FactPolicyAttachment {
			assert.NotEmpty(t, f.From, "empty PolicyArn must not emit policy_attachment")
			assert.NotEqual(t, "arn:aws:iam::111111111111:user/NoArn", f.To,
				"principal with empty PolicyArn should not receive a policy_attachment")
		}
	}
}

// ---------------------------------------------------------------------------
// Coverage Tracker (A.6)
// ---------------------------------------------------------------------------

func TestCoverageTracker(t *testing.T) {
	ct := NewCoverageTracker()
	ct.MarkIAMGAAD()
	// Mark attempted types — even if zero results, they should be true.
	ct.MarkAttempted("AWS::Lambda::Function")
	ct.MarkAttempted("AWS::EC2::Instance")
	ct.MarkAttempted("AWS::S3::Bucket")

	cov := ct.Build()
	assert.True(t, cov.IAMGAAD)
	assert.True(t, cov.LambdaExecutionRoles)
	assert.True(t, cov.LambdaResourcePolicies)
	assert.True(t, cov.EC2InstanceProfiles)
	assert.True(t, cov.S3BucketPolicies)
	assert.False(t, cov.ECSTaskRoles)
	assert.False(t, cov.CodeBuildServiceRoles)
	assert.False(t, cov.SQSQueuePolicies)
}

func TestCoverageTracker_Errors(t *testing.T) {
	ct := NewCoverageTracker()
	ct.MarkAttempted("AWS::EC2::Instance")
	ct.RecordError("ec2", "AccessDenied", "us-east-1", "us-west-2")

	cov := ct.Build()
	assert.True(t, cov.EC2InstanceProfiles, "should be true even with errors — we attempted")

	errs := ct.Errors()
	require.Len(t, errs, 1)
	assert.Equal(t, "ec2", errs[0].Source)
	assert.Equal(t, "AccessDenied", errs[0].Error)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, errs[0].Regions)
}

// ---------------------------------------------------------------------------
// Resource Policies
// ---------------------------------------------------------------------------

func TestCollectResourcePolicies(t *testing.T) {
	resources := newTestResources()
	policies := CollectResourcePolicies(resources)

	// Only the S3 bucket has a resource policy
	require.Len(t, policies, 1)
	assert.Equal(t, "arn:aws:s3:::my-bucket", policies[0].Resource)
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestIsAdmin_IAMStarPlusStsAssumeRole(t *testing.T) {
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"iam:*"}, Resource: &types.DynaString{"*"}},
		{Effect: "Allow", Action: &types.DynaString{"sts:AssumeRole"}, Resource: &types.DynaString{"*"}},
	}
	assert.True(t, isAdmin(stmts), "iam:* + sts:AssumeRole on * should be admin")
}

func TestIsAdmin_IAMStarOnly(t *testing.T) {
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"iam:*"}, Resource: &types.DynaString{"*"}},
	}
	assert.False(t, isAdmin(stmts), "iam:* alone without sts:AssumeRole should not be admin")
}

func TestIsAdmin_WildcardActionCoversIAMAndSTS(t *testing.T) {
	// A single * action covers both iam:* and sts:AssumeRole
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	assert.True(t, isAdmin(stmts))
}

func TestIsAdmin_RestrictedResource(t *testing.T) {
	stmts := []types.PolicyStatement{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"arn:aws:s3:::bucket"}},
	}
	assert.False(t, isAdmin(stmts), "should not be admin with restricted resource")
}

func TestCollectPrincipals_EmptyGAAD(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	principals := CollectPrincipals(gaad)
	assert.Empty(t, principals, "empty GAAD should produce no principals")
}

func TestCollectStructuralFacts_EmptyInputs(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()
	facts := CollectStructuralFacts(gaad, resources)
	assert.Empty(t, facts)
}

func TestCollectResources_EmptyResources(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	result := CollectResources(resources)
	assert.Empty(t, result)
}

func TestCollectStructuralFacts_ECSTaskRole(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:ecs:us-east-1:111111111111:task-definition/myapp:1", output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ARN:          "arn:aws:ecs:us-east-1:111111111111:task-definition/myapp:1",
		AccountRef:   "111111111111",
		Properties:   map[string]any{"TaskRoleArn": "arn:aws:iam::111111111111:role/ECSRole"},
	})

	facts := CollectStructuralFacts(gaad, resources)
	found := false
	for _, f := range facts {
		if f.Type == FactECSTaskRole && f.To == "arn:aws:iam::111111111111:role/ECSRole" {
			found = true
		}
	}
	assert.True(t, found, "should find ECS task role fact")
}

func TestCollectStructuralFacts_LambdaWithNoRoleProperty(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:lambda:us-east-1:111111111111:function:NoRole", output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ARN:          "arn:aws:lambda:us-east-1:111111111111:function:NoRole",
		AccountRef:   "111111111111",
		// No Properties → no execution role fact
	})

	facts := CollectStructuralFacts(gaad, resources)
	for _, f := range facts {
		assert.NotEqual(t, FactLambdaExecutionRole, f.Type, "should not create fact for Lambda without Role property")
	}
}

func TestCollectStructuralFacts_AthenaWorkGroupRole(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()
	wgARN := "arn:aws:athena:us-east-1:111111111111:workgroup/analytics"
	roleARN := "arn:aws:iam::111111111111:role/AthenaWGRole"
	resources.Set(wgARN, output.AWSResource{
		ResourceType: "AWS::Athena::WorkGroup",
		ARN:          wgARN,
		AccountRef:   "111111111111",
		// Top-level Properties.ExecutionRole — same extractProperty shape as
		// Lambda Role / ECS TaskRoleArn. Nested WorkGroupConfiguration.ExecutionRole
		// is not required by this test.
		Properties: map[string]any{"ExecutionRole": roleARN},
	})

	facts := CollectStructuralFacts(gaad, resources)
	found := false
	for _, f := range facts {
		if f.Type == StructuralFactType("athena_workgroup_role") &&
			f.From == wgARN &&
			f.To == roleARN {
			found = true
		}
	}
	assert.True(t, found, "should find athena_workgroup_role from workgroup ARN to role ARN")
}

func TestCollectStructuralFacts_SageMakerSpaceRole(t *testing.T) {
	spaceARN := "arn:aws:sagemaker:us-east-1:111111111111:space/domain/research"
	roleARN := "arn:aws:iam::111111111111:role/SpaceRole"

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "ExecutionRole", key: "ExecutionRole"},
		{name: "ExecutionRoleArn", key: "ExecutionRoleArn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
			resources := store.NewMap[output.AWSResource]()
			resources.Set(spaceARN, output.AWSResource{
				ResourceType: "AWS::SageMaker::Space",
				ARN:          spaceARN,
				AccountRef:   "111111111111",
				Properties:   map[string]any{tc.key: roleARN},
			})

			facts := CollectStructuralFacts(gaad, resources)
			found := false
			for _, f := range facts {
				if f.Type == StructuralFactType("sagemaker_space_role") &&
					f.From == spaceARN &&
					f.To == roleARN {
					found = true
				}
			}
			assert.True(t, found, "should find sagemaker_space_role from space ARN to role ARN")
		})
	}
}

func TestCollectStructuralFacts_WorkGroupAndSpaceWithoutRole(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:athena:us-east-1:111111111111:workgroup/empty", output.AWSResource{
		ResourceType: "AWS::Athena::WorkGroup",
		ARN:          "arn:aws:athena:us-east-1:111111111111:workgroup/empty",
		AccountRef:   "111111111111",
		Properties:   map[string]any{"ExecutionRole": ""},
	})
	resources.Set("arn:aws:athena:us-east-1:111111111111:workgroup/missing", output.AWSResource{
		ResourceType: "AWS::Athena::WorkGroup",
		ARN:          "arn:aws:athena:us-east-1:111111111111:workgroup/missing",
		AccountRef:   "111111111111",
	})
	resources.Set("arn:aws:sagemaker:us-east-1:111111111111:space/domain/empty", output.AWSResource{
		ResourceType: "AWS::SageMaker::Space",
		ARN:          "arn:aws:sagemaker:us-east-1:111111111111:space/domain/empty",
		AccountRef:   "111111111111",
		Properties:   map[string]any{"ExecutionRole": "", "ExecutionRoleArn": ""},
	})
	resources.Set("arn:aws:sagemaker:us-east-1:111111111111:space/domain/missing", output.AWSResource{
		ResourceType: "AWS::SageMaker::Space",
		ARN:          "arn:aws:sagemaker:us-east-1:111111111111:space/domain/missing",
		AccountRef:   "111111111111",
	})

	facts := CollectStructuralFacts(gaad, resources)
	for _, f := range facts {
		assert.NotEqual(t, StructuralFactType("athena_workgroup_role"), f.Type,
			"should not create athena_workgroup_role for WorkGroup with empty/missing ExecutionRole")
		assert.NotEqual(t, StructuralFactType("sagemaker_space_role"), f.Type,
			"should not create sagemaker_space_role for Space with empty/missing role property")
	}
}

func TestIsAdminGroup_AttachedManagedPolicy(t *testing.T) {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil,
		[]types.ManagedPolicyDetail{
			{
				Arn:        "arn:aws:iam::aws:policy/AdministratorAccess",
				PolicyName: "AdministratorAccess",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: types.Policy{Statement: &adminStmt}},
				},
			},
		})

	group := types.GroupDetail{
		Arn:       "arn:aws:iam::111111111111:group/Admin",
		GroupName: "Admin",
		AttachedManagedPolicies: []types.ManagedPolicy{
			{PolicyName: "AdministratorAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"},
		},
	}
	assert.True(t, isAdminGroup(group, gaad), "group attaching AdministratorAccess should be admin")
}

func TestIsAdminGroup_InlinePolicy(t *testing.T) {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)

	group := types.GroupDetail{
		Arn:       "arn:aws:iam::111111111111:group/InlineAdmin",
		GroupName: "InlineAdmin",
		GroupPolicyList: []types.InlinePolicy{
			{PolicyName: "FullAccess", PolicyDocument: types.Policy{Statement: &adminStmt}},
		},
	}
	assert.True(t, isAdminGroup(group, gaad), "group with inline *:* policy should be admin")
}

func TestIsAdminGroup_NonAdmin(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)

	group := types.GroupDetail{
		Arn:       "arn:aws:iam::111111111111:group/ReadOnly",
		GroupName: "ReadOnly",
		GroupPolicyList: []types.InlinePolicy{
			{PolicyName: "ReadOnly", PolicyDocument: types.Policy{Statement: &types.PolicyStatementList{
				{Effect: "Allow", Action: &types.DynaString{"s3:Get*"}, Resource: &types.DynaString{"*"}},
			}}},
		},
	}
	assert.False(t, isAdminGroup(group, gaad), "group with limited permissions should not be admin")
}

func TestIsAdminGroup_NoPolicies(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)

	group := types.GroupDetail{
		Arn:       "arn:aws:iam::111111111111:group/Empty",
		GroupName: "Empty",
	}
	assert.False(t, isAdminGroup(group, gaad), "group with no policies should not be admin")
}

func TestCollectStructuralFacts_CrossAccountTrust(t *testing.T) {
	trustStmt := types.PolicyStatementList{
		{
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: &types.DynaString{"arn:aws:iam::222222222222:role/CrossAccountRole"},
			},
			Action:   &types.DynaString{"sts:AssumeRole"},
			Resource: &types.DynaString{"arn:aws:iam::111111111111:role/TrustedRole"},
		},
	}

	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil,
		[]types.RoleDetail{
			{
				Arn:                      "arn:aws:iam::111111111111:role/TrustedRole",
				RoleName:                 "TrustedRole",
				AssumeRolePolicyDocument: types.Policy{Statement: &trustStmt},
			},
		}, nil)
	resources := store.NewMap[output.AWSResource]()

	facts := CollectStructuralFacts(gaad, resources)
	found := false
	for _, f := range facts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::111111111111:role/TrustedRole" &&
			f.To == "arn:aws:iam::222222222222:role/CrossAccountRole" {
			found = true
		}
	}
	assert.True(t, found, "should create cross-account trust relationship fact")
}
