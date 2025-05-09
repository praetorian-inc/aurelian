package types

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTags(t *testing.T) {
	testCases := []struct {
		name     string
		erd      string
		expected map[string]string
	}{
		{
			name: "Tags present",
			erd: `{
    "Identifier": "eni-0e8bade12fb6000d8",
    "TypeName": "AWS::EC2::NetworkInterface",
    "Region": "us-east-2",
    "Properties": "{\"Description\":\"EFS mount target for fs-011adcbc820abb7da (fsmt-abcdef12345678901)\",\"PrivateIpAddress\":\"172.31.11.78\",\"PrimaryIpv6Address\":\"\",\"PrivateIpAddresses\":[{\"PrivateIpAddress\":\"172.31.11.78\",\"Primary\":true}],\"SecondaryPrivateIpAddressCount\":0,\"Ipv6PrefixCount\":0,\"PrimaryPrivateIpAddress\":\"172.31.11.78\",\"Ipv4Prefixes\":[],\"Ipv4PrefixCount\":0,\"GroupSet\":[\"sg-00abcdef123456789\",\"sg-d123456d\"],\"Ipv6Prefixes\":[],\"SubnetId\":\"subnet-b1234456\",\"SourceDestCheck\":true,\"InterfaceType\":\"null\",\"SecondaryPrivateIpAddresses\":[],\"VpcId\":\"vpc-7abcdef1\",\"Id\":\"eni-0e1234567890000d8\",\"Tags\":[{\"Value\":\"arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAmazonElasticFileSystem/001540145697\",\"Key\":\"AutoTag_Creator\"},{\"Value\":\"elasticfilesystem.amazonaws.com\",\"Key\":\"AutoTag_InvokedBy\"},{\"Value\":\"2024-05-21T23:12:32Z\",\"Key\":\"AutoTag_CreateTime\"}]}",                                                                                                          "AccountId": "555045483459",
    "Arn": {
      "Partition": "aws",
      "Service": "ec2",
      "Region": "us-east-2",
      "AccountID": "555045483459",
      "Resource": "eni-0e8bade12fb6000d8"
    }
  }`,
			expected: map[string]string{
				"AutoTag_CreateTime": "2024-05-21T23:12:32Z",
				"AutoTag_Creator":    "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAmazonElasticFileSystem/001540145697",
				"AutoTag_InvokedBy":  "elasticfilesystem.amazonaws.com",
			},
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var erd EnrichedResourceDescription
			json.Unmarshal([]byte(tc.erd), &erd)

			tags := erd.Tags()
			if !reflect.DeepEqual(tags, tc.expected) {
				t.Errorf("Expected tags: %v, got: %v", tc.expected, tags)
			}
		})
	}
}

func Test_NewEnrichedResourceDescription_Service(t *testing.T) {
	erd := NewEnrichedResourceDescription("ec2.amazonaws.com", "AWS::Service", "*", "123456789012", map[string]any{})

	assert.Equal(t, "ec2.amazonaws.com", erd.Identifier)
	assert.Equal(t, "AWS::Service", erd.TypeName)
	assert.Equal(t, "*", erd.Region)
	assert.Equal(t, "123456789012", erd.AccountId)
	assert.Equal(t, "arn:aws:ec2:*:*:*", erd.Arn.String())
	assert.Equal(t, "ec2", erd.Service())
}

func Test_NewEnrichedResourceDescription_IAMPolicy(t *testing.T) {
	erd := `{
    "Identifier": "arn:aws:iam::123456789012:policy/vuln-iam-attach-user-policy-target-policy-eV6dJr4X",
    "TypeName": "AWS::IAM::ManagedPolicy", 
    "Region": "",
    "Properties": "{\"PolicyArn\":\"arn:aws:iam::123456789012:policy/vuln-iam-attach-user-policy-target-policy-eV6dJr4X\"}",
    "AccountId": "123456789012",
    "Arn": {
        "Partition": "aws",
        "Service": "iam",
        "Region": "",
        "AccountID": "123456789012",
        "Resource": "policy/vuln-iam-attach-user-policy-target-policy-eV6dJr4X"
    }
}`

	var resource EnrichedResourceDescription
	err := json.Unmarshal([]byte(erd), &resource)
	assert.NoError(t, err)

	assert.Equal(t, "arn:aws:iam::123456789012:policy/vuln-iam-attach-user-policy-target-policy-eV6dJr4X", resource.Arn.String())
}

func Test_NewEnrichedResourceDescription_IAMRole(t *testing.T) {
	erd := `{
    "Identifier": "acme-admin-access",                                                                                                                                                                                            "TypeName": "AWS::IAM::Role",                                                                                                                                                                                                 "Region": "",
    "Properties": "{\"RoleName\":\"acme-admin-access\"}",
    "AccountId": "123456789012",
    "Arn": {
      "Partition": "aws",
      "Service": "iam",
      "Region": "",
      "AccountID": "123456789012",
      "Resource": "role/acme-admin-access"
    }
}`

	var resource EnrichedResourceDescription
	err := json.Unmarshal([]byte(erd), &resource)
	assert.NoError(t, err)

	assert.Equal(t, "arn:aws:iam::123456789012:role/acme-admin-access", resource.Arn.String())
}

func Test_NewEnrichedResourceDescriptionFromRoleDL(t *testing.T) {
	roleJSON := `{
		"Path": "/",
		"RoleName": "acme-admin-access", 
		"RoleId": "AROAYCO2J6PBWTNHKCYLL",
		"Arn": "arn:aws:iam::123456789012:role/acme-admin-access",
		"CreateDate": "2024-05-10T15:06:37+00:00",
		"AssumeRolePolicyDocument": {
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": {
						"AWS": [
							"arn:aws:iam::123456789012:root",
							"arn:aws:iam::123456789012:user/ReadOnlyUser"
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
		"Tags": [],
		"RoleLastUsed": {
			"LastUsedDate": "2024-05-10T15:46:34+00:00",
			"Region": "us-east-1"
		}
	}`

	var role RoleDL
	err := json.Unmarshal([]byte(roleJSON), &role)
	assert.NoError(t, err)

	erd := NewEnrichedResourceDescriptionFromRoleDL(role)

	assert.Equal(t, "acme-admin-access", erd.Identifier)
	assert.Equal(t, "AWS::IAM::Role", erd.TypeName)
	assert.Equal(t, "", erd.Region)
	assert.Equal(t, "123456789012", erd.AccountId)
	assert.Equal(t, "arn:aws:iam::123456789012:role/acme-admin-access", erd.Arn.String())
}
