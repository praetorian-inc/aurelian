package aws

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
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

var erdStr = `
[
{                                                                                                                                                               
    "Identifier": "acme-sa-role",
    "TypeName": "AWS::IAM::Role",
    "Region": "",
    "Properties": "{\"RoleName\":\"acme-sa-role\"}",
    "AccountId": "123456789012",
    "Arn": {
      "Partition": "aws",
      "Service": "iam",
      "Region": "",
      "AccountID": "123456789012",
      "Resource": "role/acme-sa-role"
    }
  },
  {
    "Identifier": "AcmeBuild",
    "TypeName": "AWS::IAM::Role",
    "Region": "",
    "Properties": "{\"RoleName\":\"AcmeBuild\"}",
    "AccountId": "123456789012",
    "Arn": {
      "Partition": "aws",
      "Service": "iam",
      "Region": "",
      "AccountID": "123456789012",
      "Resource": "role/AcmeBuild"
    }
  }
]
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
	acmeGlueRole := strResourcetoType[types.RoleDL](acmeGlueRoleStr)
	aaPolicy := strResourcetoType[types.PoliciesDL](administratorAccessStr)

	gaad := types.Gaad{
		UserDetailList: []types.UserDL{},
		RoleDetailList: []types.RoleDL{
			acmeGlueRole,
		},
		GroupDetailList: []types.GroupDL{},
		Policies: []types.PoliciesDL{
			aaPolicy,
		},
	}

	resources := strResourcetoType[[]types.EnrichedResourceDescription](erdStr)

	pd := NewPolicyData(&gaad, nil, nil, nil, &resources)
	ga := NewGaadAnalyzer(pd)
	ps, err := ga.AnalyzePrincipalPermissions()
	assert.NoError(t, err)

	fr := ps.FullResults()
	assert.Len(t, fr, 2)

	resourceArns := []string{
		"arn:aws:iam::123456789012:role/AcmeBuild",
		"arn:aws:iam::123456789012:role/acme-sa-role",
	}

	assert.Contains(t, resourceArns, fr[0].Resource.Arn.String())
	assert.Contains(t, resourceArns, fr[1].Resource.Arn.String())

	// verify principal
	assert.Equal(t, "arn:aws:iam::123456789012:role/acme-glue-role", fr[0].Principal.(*types.RoleDL).Arn)
	assert.Equal(t, "arn:aws:iam::123456789012:role/acme-glue-role", fr[1].Principal.(*types.RoleDL).Arn)

	assert.Equal(t, "sts:AssumeRole", fr[0].Action)
	assert.Equal(t, "sts:AssumeRole", fr[1].Action)
}
