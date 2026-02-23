package gaad

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromUserDL(t *testing.T) {
	baseUser := types.UserDetail{
		Arn:      "arn:aws:iam::111122223333:user/alice",
		UserName: "alice",
		UserId:   "AIDA1234567890",
		Path:     "/",
	}

	t.Run("with explicit accountID", func(t *testing.T) {
		result := FromUserDetail(baseUser, "999988887777")
		assert.Equal(t, "999988887777", result.AccountRef)
	})

	t.Run("with empty accountID falls back to ARN", func(t *testing.T) {
		result := FromUserDetail(baseUser, "")
		assert.Equal(t, "111122223333", result.AccountRef)
	})

	t.Run("resource fields", func(t *testing.T) {
		result := FromUserDetail(baseUser, "111122223333")
		assert.Equal(t, "AWS::IAM::User", result.ResourceType)
		assert.Equal(t, baseUser.Arn, result.ResourceID)
		assert.Equal(t, baseUser.Arn, result.ARN)
		assert.Equal(t, "alice", result.DisplayName)
	})

	t.Run("OriginalData is set to user", func(t *testing.T) {
		result := FromUserDetail(baseUser, "")
		assert.Equal(t, baseUser, result.OriginalData)
	})

	t.Run("with inline policies", func(t *testing.T) {
		user := baseUser
		user.UserPolicyList = []types.InlinePolicy{
			{PolicyName: "inline1", PolicyDocument: types.Policy{Version: "2012-10-17"}},
		}
		result := FromUserDetail(user, "")
		require.Len(t, result.InlinePolicies, 1)
		assert.Equal(t, "inline1", result.InlinePolicies[0].PolicyName)
	})

	t.Run("with managed policies", func(t *testing.T) {
		user := baseUser
		user.AttachedManagedPolicies = []types.ManagedPolicy{
			{PolicyName: "ReadOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess"},
		}
		result := FromUserDetail(user, "")
		require.Len(t, result.AttachedManagedPolicies, 1)
		assert.Equal(t, "ReadOnlyAccess", result.AttachedManagedPolicies[0].PolicyName)
	})

	t.Run("with permissions boundary", func(t *testing.T) {
		user := baseUser
		user.PermissionsBoundary = types.ManagedPolicy{
			PolicyName: "Boundary",
			PolicyArn:  "arn:aws:iam::111122223333:policy/Boundary",
		}
		result := FromUserDetail(user, "")
		require.NotNil(t, result.PermissionsBoundary)
		assert.Equal(t, "Boundary", result.PermissionsBoundary.PolicyName)
		assert.Equal(t, "arn:aws:iam::111122223333:policy/Boundary", result.PermissionsBoundary.PolicyArn)
	})

	t.Run("with tags", func(t *testing.T) {
		user := baseUser
		user.Tags = []types.Tag{
			{Key: "env", Value: "prod"},
			{Key: "team", Value: "security"},
		}
		result := FromUserDetail(user, "")
		require.Len(t, result.IAMTags, 2)
		assert.Equal(t, "env", result.IAMTags[0].Key)
		assert.Equal(t, "prod", result.IAMTags[0].Value)
	})

	t.Run("with group memberships", func(t *testing.T) {
		user := baseUser
		user.GroupList = []string{"admins", "developers"}
		result := FromUserDetail(user, "")
		require.Len(t, result.GroupMemberships, 2)
		assert.Equal(t, "admins", result.GroupMemberships[0])
		assert.Equal(t, "developers", result.GroupMemberships[1])
	})
}

func TestFromRoleDL(t *testing.T) {
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Sid: "AllowAssumeRole"},
	}
	baseRole := types.RoleDetail{
		Arn:      "arn:aws:iam::111122223333:role/my-role",
		RoleName: "my-role",
		RoleId:   "AROA1234567890",
		Path:     "/",
		AssumeRolePolicyDocument: types.Policy{
			Version:   "2012-10-17",
			Statement: &stmts,
		},
	}

	t.Run("resource fields and AccountRef parsed from ARN", func(t *testing.T) {
		result := FromRoleDetail(baseRole)
		assert.Equal(t, "AWS::IAM::Role", result.ResourceType)
		assert.Equal(t, baseRole.Arn, result.ResourceID)
		assert.Equal(t, baseRole.Arn, result.ARN)
		assert.Equal(t, "my-role", result.DisplayName)
		assert.Equal(t, "111122223333", result.AccountRef)
	})

	t.Run("OriginalData is set to role", func(t *testing.T) {
		result := FromRoleDetail(baseRole)
		assert.Equal(t, baseRole, result.OriginalData)
	})

	t.Run("with assume role policy", func(t *testing.T) {
		result := FromRoleDetail(baseRole)
		require.NotNil(t, result.AssumeRolePolicy)
		assert.Equal(t, "2012-10-17", result.AssumeRolePolicy.Version)
	})

	t.Run("with inline policies", func(t *testing.T) {
		role := baseRole
		role.RolePolicyList = []types.InlinePolicy{
			{PolicyName: "role-inline", PolicyDocument: types.Policy{Version: "2012-10-17"}},
		}
		result := FromRoleDetail(role)
		require.Len(t, result.InlinePolicies, 1)
		assert.Equal(t, "role-inline", result.InlinePolicies[0].PolicyName)
	})

	t.Run("with managed policies", func(t *testing.T) {
		role := baseRole
		role.AttachedManagedPolicies = []types.ManagedPolicy{
			{PolicyName: "AdminAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"},
		}
		result := FromRoleDetail(role)
		require.Len(t, result.AttachedManagedPolicies, 1)
		assert.Equal(t, "AdminAccess", result.AttachedManagedPolicies[0].PolicyName)
	})

	t.Run("with instance profiles", func(t *testing.T) {
		role := baseRole
		role.InstanceProfileList = []types.InstanceProfile{
			{
				InstanceProfileName: "my-profile",
				Arn:                 "arn:aws:iam::111122223333:instance-profile/my-profile",
			},
		}
		result := FromRoleDetail(role)
		require.Len(t, result.InstanceProfiles, 1)
		assert.Equal(t, "my-profile", result.InstanceProfiles[0].InstanceProfileName)
	})

	t.Run("with permissions boundary", func(t *testing.T) {
		role := baseRole
		role.PermissionsBoundary = types.ManagedPolicy{
			PolicyName: "RoleBoundary",
			PolicyArn:  "arn:aws:iam::111122223333:policy/RoleBoundary",
		}
		result := FromRoleDetail(role)
		require.NotNil(t, result.PermissionsBoundary)
		assert.Equal(t, "RoleBoundary", result.PermissionsBoundary.PolicyName)
	})

	t.Run("with tags", func(t *testing.T) {
		role := baseRole
		role.Tags = []types.Tag{
			{Key: "service", Value: "lambda"},
		}
		result := FromRoleDetail(role)
		require.Len(t, result.IAMTags, 1)
		assert.Equal(t, "service", result.IAMTags[0].Key)
		assert.Equal(t, "lambda", result.IAMTags[0].Value)
	})
}

func TestFromGroupDL(t *testing.T) {
	baseGroup := types.GroupDetail{
		Arn:       "arn:aws:iam::111122223333:group/developers",
		GroupName: "developers",
		GroupId:   "AGPA1234567890",
		Path:      "/",
	}

	t.Run("resource fields", func(t *testing.T) {
		result := FromGroupDetail(baseGroup)
		assert.Equal(t, "AWS::IAM::Group", result.ResourceType)
		assert.Equal(t, baseGroup.Arn, result.ResourceID)
		assert.Equal(t, baseGroup.Arn, result.ARN)
		assert.Equal(t, "developers", result.DisplayName)
		assert.Equal(t, "111122223333", result.AccountRef)
	})

	t.Run("OriginalData is set to group", func(t *testing.T) {
		result := FromGroupDetail(baseGroup)
		assert.Equal(t, baseGroup, result.OriginalData)
	})

	t.Run("with inline policies", func(t *testing.T) {
		group := baseGroup
		group.GroupPolicyList = []types.InlinePolicy{
			{PolicyName: "group-inline", PolicyDocument: types.Policy{Version: "2012-10-17"}},
		}
		result := FromGroupDetail(group)
		require.Len(t, result.InlinePolicies, 1)
		assert.Equal(t, "group-inline", result.InlinePolicies[0].PolicyName)
	})

	t.Run("with managed policies", func(t *testing.T) {
		group := baseGroup
		group.AttachedManagedPolicies = []types.ManagedPolicy{
			{PolicyName: "ViewOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ViewOnlyAccess"},
		}
		result := FromGroupDetail(group)
		require.Len(t, result.AttachedManagedPolicies, 1)
		assert.Equal(t, "ViewOnlyAccess", result.AttachedManagedPolicies[0].PolicyName)
	})
}

func TestFromPolicyDL(t *testing.T) {
	basePolicy := types.ManagedPolicyDetail{
		PolicyName:       "MyPolicy",
		PolicyId:         "ANPA1234567890",
		Arn:              "arn:aws:iam::111122223333:policy/MyPolicy",
		Path:             "/",
		DefaultVersionId: "v1",
		IsAttachable:     true,
	}

	t.Run("resource fields", func(t *testing.T) {
		result := FromManagedPolicyDetail(basePolicy)
		assert.Equal(t, "AWS::IAM::ManagedPolicy", result.ResourceType)
		assert.Equal(t, basePolicy.Arn, result.ResourceID)
		assert.Equal(t, basePolicy.Arn, result.ARN)
		assert.Equal(t, "MyPolicy", result.DisplayName)
		assert.Equal(t, "111122223333", result.AccountRef)
	})

	t.Run("OriginalData is set to policy", func(t *testing.T) {
		result := FromManagedPolicyDetail(basePolicy)
		assert.Equal(t, basePolicy, result.OriginalData)
	})

	t.Run("with policy versions", func(t *testing.T) {
		policy := basePolicy
		policy.PolicyVersionList = []types.PolicyVersion{
			{
				VersionId:        "v1",
				IsDefaultVersion: true,
				Document:         types.Policy{Version: "2012-10-17"},
			},
			{
				VersionId:        "v2",
				IsDefaultVersion: false,
				Document:         types.Policy{Version: "2012-10-17"},
			},
		}
		result := FromManagedPolicyDetail(policy)
		require.Len(t, result.PolicyVersions, 2)
		assert.Equal(t, "v1", result.PolicyVersions[0].VersionId)
		assert.True(t, result.PolicyVersions[0].IsDefaultVersion)
		assert.Equal(t, "v2", result.PolicyVersions[1].VersionId)
		assert.False(t, result.PolicyVersions[1].IsDefaultVersion)
	})
}

func TestFromGAAD(t *testing.T) {
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Sid: "AllowAssumeRole"},
	}

	t.Run("full GAAD with multiple entities", func(t *testing.T) {
		gaad := &types.AuthorizationAccountDetails{
			UserDetailList: []types.UserDetail{
				{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice"},
				{Arn: "arn:aws:iam::111122223333:user/bob", UserName: "bob"},
			},
			RoleDetailList: []types.RoleDetail{
				{
					Arn:      "arn:aws:iam::111122223333:role/role1",
					RoleName: "role1",
					AssumeRolePolicyDocument: types.Policy{
						Version:   "2012-10-17",
						Statement: &stmts,
					},
				},
				{
					Arn:      "arn:aws:iam::111122223333:role/role2",
					RoleName: "role2",
					AssumeRolePolicyDocument: types.Policy{
						Version:   "2012-10-17",
						Statement: &stmts,
					},
				},
			},
			GroupDetailList: []types.GroupDetail{
				{Arn: "arn:aws:iam::111122223333:group/devs", GroupName: "devs"},
			},
			Policies: []types.ManagedPolicyDetail{
				{Arn: "arn:aws:iam::111122223333:policy/pol1", PolicyName: "pol1"},
			},
		}

		result := FromGAAD(gaad, "999988887777")
		require.Len(t, result, 6)

		// Verify ordering: users first, then roles, then groups, then policies
		assert.Equal(t, "AWS::IAM::User", result[0].ResourceType)
		assert.Equal(t, "alice", result[0].DisplayName)
		assert.Equal(t, "AWS::IAM::User", result[1].ResourceType)
		assert.Equal(t, "bob", result[1].DisplayName)
		assert.Equal(t, "AWS::IAM::Role", result[2].ResourceType)
		assert.Equal(t, "role1", result[2].DisplayName)
		assert.Equal(t, "AWS::IAM::Role", result[3].ResourceType)
		assert.Equal(t, "role2", result[3].DisplayName)
		assert.Equal(t, "AWS::IAM::Group", result[4].ResourceType)
		assert.Equal(t, "devs", result[4].DisplayName)
		assert.Equal(t, "AWS::IAM::ManagedPolicy", result[5].ResourceType)
		assert.Equal(t, "pol1", result[5].DisplayName)
	})

	t.Run("accountID is passed through to user conversion", func(t *testing.T) {
		gaad := &types.AuthorizationAccountDetails{
			UserDetailList: []types.UserDetail{
				{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice"},
			},
		}
		result := FromGAAD(gaad, "explicit-account")
		require.Len(t, result, 1)
		assert.Equal(t, "explicit-account", result[0].AccountRef)
	})

	t.Run("empty GAAD returns empty slice", func(t *testing.T) {
		gaad := &types.AuthorizationAccountDetails{}
		result := FromGAAD(gaad, "123456789012")
		require.Empty(t, result)
	})
}

func TestDeduplicateByARN(t *testing.T) {
	t.Run("duplicates removed", func(t *testing.T) {
		entities := []output.AWSIAMResource{
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice", DisplayName: "alice"}},
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice", DisplayName: "alice-dup"}},
		}
		result := DeduplicateByARN(entities)
		require.Len(t, result, 1)
	})

	t.Run("first entry wins", func(t *testing.T) {
		entities := []output.AWSIAMResource{
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice", DisplayName: "first"}},
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice", DisplayName: "second"}},
		}
		result := DeduplicateByARN(entities)
		require.Len(t, result, 1)
		assert.Equal(t, "first", result[0].DisplayName)
	})

	t.Run("empty ARN falls back to ResourceID for dedup key", func(t *testing.T) {
		entities := []output.AWSIAMResource{
			{AWSResource: output.AWSResource{ARN: "", ResourceID: "resource-1", DisplayName: "first"}},
			{AWSResource: output.AWSResource{ARN: "", ResourceID: "resource-1", DisplayName: "second"}},
		}
		result := DeduplicateByARN(entities)
		require.Len(t, result, 1)
		assert.Equal(t, "first", result[0].DisplayName)
	})

	t.Run("no duplicates retains all", func(t *testing.T) {
		entities := []output.AWSIAMResource{
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice"}},
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/bob"}},
			{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:role/my-role"}},
		}
		result := DeduplicateByARN(entities)
		require.Len(t, result, 3)
	})

	t.Run("empty input returns empty result", func(t *testing.T) {
		result := DeduplicateByARN([]output.AWSIAMResource{})
		require.Empty(t, result)
	})
}

func TestExtractResourceTags(t *testing.T) {
	tests := []struct {
		name string
		r    *output.AWSResource
		want map[string]string
	}{
		{
			name: "nil resource returns empty map",
			r:    nil,
			want: map[string]string{},
		},
		{
			name: "nil Properties returns empty map",
			r:    &output.AWSResource{},
			want: map[string]string{},
		},
		{
			name: "no Tags key in Properties returns empty map",
			r: &output.AWSResource{
				Properties: map[string]any{
					"OtherKey": "some-value",
				},
			},
			want: map[string]string{},
		},
		{
			name: "invalid Tags type returns empty map",
			r: &output.AWSResource{
				Properties: map[string]any{
					"Tags": "not-a-list",
				},
			},
			want: map[string]string{},
		},
		{
			name: "valid tags extracted correctly",
			r: &output.AWSResource{
				Properties: map[string]any{
					"Tags": []any{
						map[string]any{"Key": "env", "Value": "prod"},
						map[string]any{"Key": "team", "Value": "security"},
					},
				},
			},
			want: map[string]string{
				"env":  "prod",
				"team": "security",
			},
		},
		{
			name: "tag with empty Key is skipped",
			r: &output.AWSResource{
				Properties: map[string]any{
					"Tags": []any{
						map[string]any{"Key": "", "Value": "orphan"},
						map[string]any{"Key": "valid", "Value": "value"},
					},
				},
			},
			want: map[string]string{
				"valid": "value",
			},
		},
		{
			name: "tag item is not a map is skipped",
			r: &output.AWSResource{
				Properties: map[string]any{
					"Tags": []any{
						"not-a-map",
						map[string]any{"Key": "ok", "Value": "fine"},
					},
				},
			},
			want: map[string]string{
				"ok": "fine",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResourceTags(tt.r)
			assert.Equal(t, tt.want, got)
		})
	}
}
