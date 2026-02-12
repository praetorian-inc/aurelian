package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGaadUnmarshal(t *testing.T) {
	t.Run("full GAAD with all detail lists", func(t *testing.T) {
		input := `{
			"UserDetailList": [
				{
					"Arn": "arn:aws:iam::123456789012:user/admin",
					"UserName": "admin",
					"UserId": "AIDAEXAMPLE1",
					"Path": "/",
					"CreateDate": "2023-01-01T00:00:00Z",
					"GroupList": ["Admins"],
					"Tags": [{"Key": "env", "Value": "prod"}],
					"UserPolicyList": [],
					"AttachedManagedPolicies": [
						{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
					]
				}
			],
			"RoleDetailList": [
				{
					"Arn": "arn:aws:iam::123456789012:role/LambdaRole",
					"RoleName": "LambdaRole",
					"RoleId": "AROAEXAMPLE1",
					"Path": "/service-role/",
					"CreateDate": "2023-06-15T00:00:00Z",
					"AssumeRolePolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [{
							"Effect": "Allow",
							"Principal": {"Service": "lambda.amazonaws.com"},
							"Action": "sts:AssumeRole"
						}]
					},
					"RolePolicyList": [],
					"AttachedManagedPolicies": [],
					"InstanceProfileList": []
				}
			],
			"GroupDetailList": [
				{
					"Path": "/",
					"GroupName": "Admins",
					"GroupId": "AGPAEXAMPLE1",
					"Arn": "arn:aws:iam::123456789012:group/Admins",
					"CreateDate": "2023-01-01T00:00:00Z",
					"GroupPolicyList": [],
					"AttachedManagedPolicies": []
				}
			],
			"Policies": []
		}`

		var gaad Gaad
		err := json.Unmarshal([]byte(input), &gaad)
		require.NoError(t, err)

		require.Len(t, gaad.UserDetailList, 1)
		assert.Equal(t, "admin", gaad.UserDetailList[0].UserName)
		assert.Equal(t, "arn:aws:iam::123456789012:user/admin", gaad.UserDetailList[0].Arn)
		assert.Equal(t, []string{"Admins"}, gaad.UserDetailList[0].GroupList)
		require.Len(t, gaad.UserDetailList[0].Tags, 1)
		assert.Equal(t, "env", gaad.UserDetailList[0].Tags[0].Key)
		assert.Equal(t, "prod", gaad.UserDetailList[0].Tags[0].Value)
		require.Len(t, gaad.UserDetailList[0].AttachedManagedPolicies, 1)
		assert.Equal(t, "AdministratorAccess", gaad.UserDetailList[0].AttachedManagedPolicies[0].PolicyName)

		require.Len(t, gaad.RoleDetailList, 1)
		assert.Equal(t, "LambdaRole", gaad.RoleDetailList[0].RoleName)
		assert.Equal(t, "/service-role/", gaad.RoleDetailList[0].Path)
		require.NotNil(t, gaad.RoleDetailList[0].AssumeRolePolicyDocument.Statement)

		require.Len(t, gaad.GroupDetailList, 1)
		assert.Equal(t, "Admins", gaad.GroupDetailList[0].GroupName)

		assert.Empty(t, gaad.Policies)
	})

	t.Run("empty GAAD parses with empty lists", func(t *testing.T) {
		input := `{
			"UserDetailList": [],
			"RoleDetailList": [],
			"GroupDetailList": [],
			"Policies": []
		}`

		var gaad Gaad
		err := json.Unmarshal([]byte(input), &gaad)
		require.NoError(t, err)
		assert.Empty(t, gaad.UserDetailList)
		assert.Empty(t, gaad.RoleDetailList)
		assert.Empty(t, gaad.GroupDetailList)
		assert.Empty(t, gaad.Policies)
	})
}

func TestDefaultPolicyDocument(t *testing.T) {
	t.Run("returns default version document", func(t *testing.T) {
		stmts := PolicyStatementList{
			{Effect: "Allow", Action: NewDynaString([]string{"s3:*"}), Resource: NewDynaString([]string{"*"})},
		}
		policy := PoliciesDL{
			PolicyName:       "TestPolicy",
			DefaultVersionId: "v2",
			PolicyVersionList: []PoliciesVL{
				{
					VersionId:        "v1",
					IsDefaultVersion: false,
					Document: Policy{
						Version:   "2012-10-17",
						Statement: &PolicyStatementList{{Effect: "Deny", Action: NewDynaString([]string{"*"}), Resource: NewDynaString([]string{"*"})}},
					},
				},
				{
					VersionId:        "v2",
					IsDefaultVersion: true,
					Document: Policy{
						Version:   "2012-10-17",
						Statement: &stmts,
					},
				},
			},
		}

		result := policy.DefaultPolicyDocument()
		require.NotNil(t, result)
		assert.Equal(t, "2012-10-17", result.Version)
		require.NotNil(t, result.Statement)
		assert.Equal(t, "Allow", (*result.Statement)[0].Effect)
	})

	t.Run("returns nil when no default version exists", func(t *testing.T) {
		policy := PoliciesDL{
			PolicyName: "NoDefault",
			PolicyVersionList: []PoliciesVL{
				{
					VersionId:        "v1",
					IsDefaultVersion: false,
					Document: Policy{
						Version:   "2012-10-17",
						Statement: &PolicyStatementList{{Effect: "Deny", Action: NewDynaString([]string{"*"}), Resource: NewDynaString([]string{"*"})}},
					},
				},
			},
		}

		result := policy.DefaultPolicyDocument()
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty version list", func(t *testing.T) {
		policy := PoliciesDL{
			PolicyName:    "EmptyVersions",
			PolicyVersionList: []PoliciesVL{},
		}

		result := policy.DefaultPolicyDocument()
		assert.Nil(t, result)
	})
}

func TestRoleDLAssumeRolePolicyDocument(t *testing.T) {
	t.Run("role with assume role policy document containing service principal", func(t *testing.T) {
		input := `{
			"Arn": "arn:aws:iam::123456789012:role/LambdaExec",
			"RoleName": "LambdaExec",
			"RoleId": "AROAEXAMPLE",
			"Path": "/",
			"CreateDate": "2023-01-01T00:00:00Z",
			"AssumeRolePolicyDocument": {
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"Service": "lambda.amazonaws.com"},
					"Action": "sts:AssumeRole"
				}]
			},
			"RolePolicyList": [],
			"AttachedManagedPolicies": [],
			"InstanceProfileList": []
		}`

		var role RoleDL
		err := json.Unmarshal([]byte(input), &role)
		require.NoError(t, err)
		assert.Equal(t, "LambdaExec", role.RoleName)
		require.NotNil(t, role.AssumeRolePolicyDocument.Statement)
		stmts := *role.AssumeRolePolicyDocument.Statement
		require.Len(t, stmts, 1)
		assert.Equal(t, "Allow", stmts[0].Effect)
		require.NotNil(t, stmts[0].Principal)
		require.NotNil(t, stmts[0].Principal.Service)
		assert.Equal(t, DynaString{"lambda.amazonaws.com"}, *stmts[0].Principal.Service)
	})
}

func TestRoleDLWithInstanceProfiles(t *testing.T) {
	t.Run("role with instance profile parses correctly", func(t *testing.T) {
		input := `{
			"Arn": "arn:aws:iam::123456789012:role/EC2Role",
			"RoleName": "EC2Role",
			"RoleId": "AROAEXAMPLE2",
			"Path": "/",
			"CreateDate": "2023-01-01T00:00:00Z",
			"AssumeRolePolicyDocument": {
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"Service": "ec2.amazonaws.com"},
					"Action": "sts:AssumeRole"
				}]
			},
			"RolePolicyList": [],
			"AttachedManagedPolicies": [],
			"InstanceProfileList": [{
				"Path": "/",
				"InstanceProfileName": "EC2-Profile",
				"InstanceProfileId": "AIPAEXAMPLE",
				"Arn": "arn:aws:iam::123456789012:instance-profile/EC2-Profile",
				"CreateDate": "2023-01-01T00:00:00Z",
				"Roles": [{
					"Path": "/",
					"RoleName": "EC2Role",
					"RoleId": "AROAEXAMPLE2",
					"Arn": "arn:aws:iam::123456789012:role/EC2Role",
					"CreateDate": "2023-01-01T00:00:00Z",
					"AssumeRolePolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [{
							"Effect": "Allow",
							"Principal": {"Service": "ec2.amazonaws.com"},
							"Action": "sts:AssumeRole"
						}]
					}
				}]
			}]
		}`

		var role RoleDL
		err := json.Unmarshal([]byte(input), &role)
		require.NoError(t, err)
		require.Len(t, role.InstanceProfileList, 1)
		assert.Equal(t, "EC2-Profile", role.InstanceProfileList[0].InstanceProfileName)
		require.Len(t, role.InstanceProfileList[0].Roles, 1)
		assert.Equal(t, "EC2Role", role.InstanceProfileList[0].Roles[0].RoleName)
	})
}

func TestUserDLWithInlinePolicies(t *testing.T) {
	t.Run("user with inline policy parses correctly", func(t *testing.T) {
		input := `{
			"Arn": "arn:aws:iam::123456789012:user/developer",
			"UserName": "developer",
			"UserId": "AIDAEXAMPLE2",
			"Path": "/",
			"CreateDate": "2023-03-01T00:00:00Z",
			"GroupList": [],
			"Tags": [],
			"UserPolicyList": [{
				"PolicyName": "InlineS3Access",
				"PolicyDocument": {
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:ListBucket"],
						"Resource": "arn:aws:s3:::dev-bucket/*"
					}]
				}
			}],
			"AttachedManagedPolicies": []
		}`

		var user UserDL
		err := json.Unmarshal([]byte(input), &user)
		require.NoError(t, err)
		assert.Equal(t, "developer", user.UserName)
		require.Len(t, user.UserPolicyList, 1)
		assert.Equal(t, "InlineS3Access", user.UserPolicyList[0].PolicyName)
		require.NotNil(t, user.UserPolicyList[0].PolicyDocument.Statement)
		stmts := *user.UserPolicyList[0].PolicyDocument.Statement
		require.Len(t, stmts, 1)
		assert.Equal(t, "Allow", stmts[0].Effect)
		require.NotNil(t, stmts[0].Action)
		assert.Len(t, *stmts[0].Action, 2)
	})
}

func TestGroupDLWithPolicies(t *testing.T) {
	t.Run("group with inline and managed policies", func(t *testing.T) {
		input := `{
			"Path": "/",
			"GroupName": "Developers",
			"GroupId": "AGPAEXAMPLE2",
			"Arn": "arn:aws:iam::123456789012:group/Developers",
			"CreateDate": "2023-01-01T00:00:00Z",
			"GroupPolicyList": [{
				"PolicyName": "GroupInlinePolicy",
				"PolicyDocument": {
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Action": "codecommit:*",
						"Resource": "*"
					}]
				}
			}],
			"AttachedManagedPolicies": [
				{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
			]
		}`

		var group GroupDL
		err := json.Unmarshal([]byte(input), &group)
		require.NoError(t, err)
		assert.Equal(t, "Developers", group.GroupName)
		require.Len(t, group.GroupPolicyList, 1)
		assert.Equal(t, "GroupInlinePolicy", group.GroupPolicyList[0].PolicyName)
		require.Len(t, group.AttachedManagedPolicies, 1)
		assert.Equal(t, "ReadOnlyAccess", group.AttachedManagedPolicies[0].PolicyName)
		assert.Equal(t, "arn:aws:iam::aws:policy/ReadOnlyAccess", group.AttachedManagedPolicies[0].PolicyArn)
	})
}

func TestPoliciesDLWithVersions(t *testing.T) {
	t.Run("managed policy with multiple versions", func(t *testing.T) {
		input := `{
			"PolicyName": "CustomPolicy",
			"PolicyId": "ANPAEXAMPLE",
			"Arn": "arn:aws:iam::123456789012:policy/CustomPolicy",
			"Path": "/",
			"DefaultVersionId": "v2",
			"AttachmentCount": 3,
			"PermissionsBoundaryUsageCount": 0,
			"IsAttachable": true,
			"CreateDate": "2023-01-01T00:00:00Z",
			"UpdateDate": "2023-06-01T00:00:00Z",
			"PolicyVersionList": [
				{
					"VersionId": "v1",
					"IsDefaultVersion": false,
					"CreateDate": "2023-01-01T00:00:00Z",
					"Document": {
						"Version": "2012-10-17",
						"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
					}
				},
				{
					"VersionId": "v2",
					"IsDefaultVersion": true,
					"CreateDate": "2023-06-01T00:00:00Z",
					"Document": {
						"Version": "2012-10-17",
						"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}]
					}
				}
			]
		}`

		var pol PoliciesDL
		err := json.Unmarshal([]byte(input), &pol)
		require.NoError(t, err)
		assert.Equal(t, "CustomPolicy", pol.PolicyName)
		assert.Equal(t, 3, pol.AttachmentCount)
		assert.True(t, pol.IsAttachable)
		require.Len(t, pol.PolicyVersionList, 2)

		defaultDoc := pol.DefaultPolicyDocument()
		require.NotNil(t, defaultDoc)
		require.NotNil(t, defaultDoc.Statement)
		stmts := *defaultDoc.Statement
		require.Len(t, stmts, 1)
		require.NotNil(t, stmts[0].Action)
		assert.Len(t, *stmts[0].Action, 2)
	})
}
