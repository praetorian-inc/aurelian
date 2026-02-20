package iam_test

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
)

var acmeGlueRoleStr = `
{
  "Path": "/",
  "RoleName": "acme-glue-role",
  "RoleId": "AROAJ7KQL3MF8P5TD9VRH",
  "Arn": "arn:aws:iam::123456789012:role/acme-glue-role",
  "CreateDate": "2024-05-10T07:19:11+00:00",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
      "Service": "glue.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
    ]
  },
  "InstanceProfileList": [],
  "RolePolicyList": [
    {
    "PolicyName": "AssumeRolePolicy",
    "PolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
      {
        "Sid": "VisualEditor0",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
      }
      ]
    }
    }
  ],
  "AttachedManagedPolicies": [],
  "Tags": [],
  "RoleLastUsed": {
    "LastUsedDate": "2024-05-10T15:44:33+00:00",
    "Region": "us-east-1"
  }
}
`

var acmeAdminRoleStr = `
{
  "Path": "/",
  "RoleName": "acme-admin-access",
  "RoleId": "AROATK47XM9PL3GD5QSRB",
  "Arn": "arn:aws:iam::123456789012:role/acme-admin-access",
  "CreateDate": "2024-05-10T15:06:37+00:00",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": [
            "arn:aws:iam::123456789012:user/ReadOnlyUser",
            "arn:aws:iam::123456789012:root"
          ]
        },
        "Action": "sts:AssumeRole",
        "Condition": {}
      }
    ]
  },
  "InstanceProfileList": [],
  "RolePolicyList": [],
  "AttachedManagedPolicies": [
    {
      "PolicyName": "AdministratorAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ],
  "Tags": [
    {
      "Key": "AutoTag_CreateTime",
      "Value": "2024-05-10T15:06:37Z"
    }
  ],
  "RoleLastUsed": {
    "LastUsedDate": "2024-05-10T15:46:34+00:00",
    "Region": "us-east-1"
  }
}
`

var administratorAccessStr = `
{
  "PolicyName": "AdministratorAccess",
  "PolicyId": "ANPAIWMBCKSKIEE64ZLYK",
  "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
  "Path": "/",
  "DefaultVersionId": "v1",
  "AttachmentCount": 18,
  "PermissionsBoundaryUsageCount": 1,
  "IsAttachable": true,
  "CreateDate": "2015-02-06T18:39:46+00:00",
  "UpdateDate": "2015-02-06T18:39:46+00:00",
  "PolicyVersionList": [
    {
      "Document": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
          }
        ]
      },
      "VersionId": "v1",
      "IsDefaultVersion": true,
      "CreateDate": "2015-02-06T18:39:46+00:00"
    }
  ]
}
`

func strResourcetoType[T any](str string) T {
	var res T

	err := json.Unmarshal([]byte(str), &res)
	if err != nil {
		panic(err)
	}
	return res
}

func Test_AssumeRole(t *testing.T) {
	acmeGlueRole := strResourcetoType[types.RoleDetail](acmeGlueRoleStr)
	aaPolicy := strResourcetoType[types.ManagedPolicyDetail](administratorAccessStr)

	gaadData := &types.AuthorizationAccountDetails{
		UserDetailList: []types.UserDetail{},
		RoleDetailList: []types.RoleDetail{
			acmeGlueRole,
		},
		GroupDetailList: []types.GroupDetail{},
		Policies: []types.ManagedPolicyDetail{
			aaPolicy,
		},
	}

	resources := []output.AWSResource{
		{ResourceType: "AWS::IAM::Role", ResourceID: "acme-sa-role", ARN: "arn:aws:iam:123456789012:role/acme-sa-role", AccountRef: "123456789012"},
		{ResourceType: "AWS::IAM::Role", ResourceID: "AcmeBuild", ARN: "arn:aws:iam:123456789012:role/AcmeBuild", AccountRef: "123456789012"},
	}

	analyzer := gaad.NewGaadAnalyzer()
	fr, err := analyzer.Analyze(gaadData, nil, resources)
	assert.NoError(t, err)

	// After the AssumeRole trust policy fix, only valid edges are created:
	// - glue.amazonaws.com can assume acme-glue-role (trust policy allows service principal)
	// - acme-glue-role CANNOT assume other roles because:
	//   1. Other roles (acme-sa-role, AcmeBuild) don't have trust policies in GAAD allowing acme-glue-role
	//   2. AssumeRole requires BOTH identity policy AND trust policy to allow
	assert.Len(t, fr, 1)
}

func Test_CreateMapsToService(t *testing.T) {
	lambdaCreate := `
{
  "Path": "/",
  "RoleName": "LambdaCreationRole",
  "RoleId": "AROAEXAMPLEID",
  "Arn": "arn:aws:iam::123456789012:role/LambdaCreationRole",
  "CreateDate": "2025-04-10T00:00:00Z",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  },
  "RolePolicyList": [
    {
      "PolicyName": "LambdaCreatePolicy",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "lambda:CreateFunction"
            ],
            "Resource": "*"
          }
        ]
      }
    }
  ]
}
`
	lambdaCreateRole := strResourcetoType[types.RoleDetail](lambdaCreate)

	gaadData := &types.AuthorizationAccountDetails{
		UserDetailList: []types.UserDetail{},
		RoleDetailList: []types.RoleDetail{
			lambdaCreateRole,
		},
		GroupDetailList: []types.GroupDetail{},
		Policies:        []types.ManagedPolicyDetail{},
	}

	resources := []output.AWSResource{
		{ResourceType: "AWS::IAM::Role", ResourceID: "acme-sa-role", ARN: "arn:aws:iam:123456789012:role/acme-sa-role", AccountRef: "123456789012"},
		{ResourceType: "AWS::IAM::Role", ResourceID: "AcmeBuild", ARN: "arn:aws:iam:123456789012:role/AcmeBuild", AccountRef: "123456789012"},
		{ResourceType: "AWS::Service", ResourceID: "lambda.amazonaws.com", ARN: "arn:aws:lambda:*:*:*"},
		{ResourceType: "AWS::Lambda::Function", ResourceID: "arn:aws:lambda:us-east-1:123456789012:function:my-function", ARN: "arn:aws:lambda:us-east-1:123456789012:function:my-function", Region: "us-east-1", AccountRef: "123456789012"},
	}

	analyzer := gaad.NewGaadAnalyzer()
	fr, err := analyzer.Analyze(gaadData, nil, resources)
	assert.NoError(t, err)

	// Expected results:
	// 1. lambda.amazonaws.com can assume LambdaCreationRole (trust policy allows)
	// 2. LambdaCreationRole can lambda:CreateFunction on the lambda service resource
	//    (now correctly evaluated using ARN-format identifiers)
	assert.Len(t, fr, 2)
}

func Test_PrivilegeEscalation(t *testing.T) {
	adminRoleStr := `
{
  "Path": "/",
  "RoleName": "admin",
  "RoleId": "AROATK47XM9PADMIN0001",
  "Arn": "arn:aws:iam::123456789012:role/admin",
  "CreateDate": "2024-05-10T15:06:37+00:00",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::123456789012:role/low-priv"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  },
  "InstanceProfileList": [],
  "RolePolicyList": [],
  "AttachedManagedPolicies": [
    {
      "PolicyName": "AdministratorAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ],
  "Tags": [],
  "RoleLastUsed": {
    "LastUsedDate": "2024-05-10T15:46:34+00:00",
    "Region": "us-east-1"
  }
}`

	lowPrivRoleStr := `
{
  "Path": "/",
  "RoleName": "low-priv",
  "RoleId": "AROATK47XM9PLOWPRIV01",
  "Arn": "arn:aws:iam::123456789012:role/low-priv",
  "CreateDate": "2024-05-10T07:19:11+00:00",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  },
  "InstanceProfileList": [],
  "RolePolicyList": [
    {
      "PolicyName": "AssumeAdminPolicy",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/admin"
          }
        ]
      }
    }
  ],
  "AttachedManagedPolicies": [],
  "Tags": [],
  "RoleLastUsed": {}
}`

	administratorAccessPolicy := strResourcetoType[types.ManagedPolicyDetail](administratorAccessStr)
	adminRole := strResourcetoType[types.RoleDetail](adminRoleStr)
	lowPrivRole := strResourcetoType[types.RoleDetail](lowPrivRoleStr)

	gaadData := &types.AuthorizationAccountDetails{
		UserDetailList: []types.UserDetail{},
		RoleDetailList: []types.RoleDetail{
			adminRole,
			lowPrivRole,
		},
		GroupDetailList: []types.GroupDetail{},
		Policies: []types.ManagedPolicyDetail{
			administratorAccessPolicy,
		},
	}

	resources := []output.AWSResource{
		{ResourceType: "AWS::IAM::Role", ResourceID: "admin", ARN: "arn:aws:iam:123456789012:role/admin", AccountRef: "123456789012", Properties: map[string]any{"RoleName": "admin"}},
		{ResourceType: "AWS::IAM::Role", ResourceID: "low-priv", ARN: "arn:aws:iam:123456789012:role/low-priv", AccountRef: "123456789012", Properties: map[string]any{"RoleName": "low-priv"}},
	}

	analyzer := gaad.NewGaadAnalyzer()
	fr, err := analyzer.Analyze(gaadData, nil, resources)
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, len(fr), 1, "Expected at least one result")

	// Find the specific result for low-priv assuming admin role
	var privilegeEscalationFound bool
	for _, rel := range fr {
		if rel.Principal.DisplayName == "low-priv" &&
			rel.Action == "sts:AssumeRole" &&
			rel.Resource.ResourceType == "AWS::IAM::Role" &&
			rel.Resource.DisplayName == "admin" {
			privilegeEscalationFound = true
			break
		}
	}

	assert.True(t, privilegeEscalationFound, "low-priv role should be able to assume the admin role")
}
