package types

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
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

func TestNewEnrichedResourceDescriptionFromSQS(t *testing.T) {
	queueJSON := `{
		"Identifier": "https://sqs.us-east-2.amazonaws.com/411435703965/ChariotTest",
		"Properties": "{\"QueueUrl\":\"https://sqs.us-east-2.amazonaws.com/411435703965/ChariotTest\"}"
	}`

	var queue cctypes.ResourceDescription
	err := json.Unmarshal([]byte(queueJSON), &queue)
	assert.NoError(t, err)

	erd := NewEnrichedResourceDescription(*queue.Identifier, "AWS::SQS::Queue", "us-east-2", "411435703965", map[string]any{})

	assert.Equal(t, "ChariotTest", erd.Identifier)
	assert.Equal(t, "AWS::SQS::Queue", erd.TypeName)
	assert.Equal(t, "us-east-2", erd.Region)
	assert.Equal(t, "411435703965", erd.AccountId)
	assert.Equal(t, "arn:aws:sqs:us-east-2:411435703965:ChariotTest", erd.Arn.String())
}

func TestNewEnrichedResourceDescription(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		typeName   string
		region     string
		accountId  string
		properties interface{}
		expected   EnrichedResourceDescription
	}{
		{
			name:       "SQS Queue",
			identifier: "https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue",
			typeName:   "AWS::SQS::Queue",
			region:     "us-west-2",
			accountId:  "123456789012",
			properties: nil,
			expected: EnrichedResourceDescription{
				Identifier: "MyQueue",
				TypeName:   "AWS::SQS::Queue",
				Region:     "us-west-2",
				AccountId:  "123456789012",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "sqs",
					Region:    "us-west-2",
					AccountID: "123456789012",
					Resource:  "MyQueue",
				},
			},
		},
		{
			name:       "EC2 Instance",
			identifier: "i-1234567890abcdef0",
			typeName:   "AWS::EC2::Instance",
			region:     "us-west-2",
			accountId:  "123456789012",
			properties: nil,
			expected: EnrichedResourceDescription{
				Identifier: "i-1234567890abcdef0",
				TypeName:   "AWS::EC2::Instance",
				Region:     "us-west-2",
				AccountId:  "123456789012",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "ec2",
					Region:    "us-west-2",
					AccountID: "123456789012",
					Resource:  "instance/i-1234567890abcdef0",
				},
			},
		},
		{
			name:       "S3 Bucket",
			identifier: "my-bucket",
			typeName:   "AWS::S3::Bucket",
			region:     "",
			accountId:  "",
			properties: nil,
			expected: EnrichedResourceDescription{
				Identifier: "my-bucket",
				TypeName:   "AWS::S3::Bucket",
				Region:     "",
				AccountId:  "",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "s3",
					Region:    "",
					AccountID: "",
					Resource:  "my-bucket",
				},
			},
		},
		{
			name:       "Generic ARN",
			identifier: "arn:aws:lambda:us-west-2:123456789012:function:my-function",
			typeName:   "AWS::Lambda::Function",
			region:     "us-west-2",
			accountId:  "123456789012",
			properties: nil,
			expected: EnrichedResourceDescription{
				Identifier: "arn:aws:lambda:us-west-2:123456789012:function:my-function",
				TypeName:   "AWS::Lambda::Function",
				Region:     "us-west-2",
				AccountId:  "123456789012",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "lambda",
					Region:    "us-west-2",
					AccountID: "123456789012",
					Resource:  "function:my-function",
				},
			},
		},
		{
			name:       "S3 Bucket",
			identifier: "my_bucket",
			typeName:   "AWS::S3::Bucket",
			region:     "",
			accountId:  "123456789012",
			properties: nil,
			expected: EnrichedResourceDescription{
				Identifier: "my_bucket",
				TypeName:   "AWS::S3::Bucket",
				Region:     "",
				AccountId:  "123456789012",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "s3",
					Region:    "",
					AccountID: "",
					Resource:  "my_bucket",
				},
			},
		},
		{
			name:       "arn as identifier",
			identifier: "arn:aws:cloudtrail:us-east-2:123456789012:channel/aws-service-channel/resource-explorer-2/47e5a5bc-4359-4556-81bc-9a34cfb4e89c",
			typeName:   "AWS::CloudTrail::Channel",
			region:     "us-east-2",
			accountId:  "123456789012",
			properties: "{\"ChannelArn\":\"arn:aws:cloudtrail:us-east-2:123456789012:channel/aws-service-channel/resource-explorer-2/47e5a5bc-4359-4556-81bc-9a34cfb4e89c\",\"Name\":\"aws-service-channel/resource-explorer-2/default\"}",
			expected: EnrichedResourceDescription{
				Identifier: "arn:aws:cloudtrail:us-east-2:123456789012:channel/aws-service-channel/resource-explorer-2/47e5a5bc-4359-4556-81bc-9a34cfb4e89c",
				TypeName:   "AWS::CloudTrail::Channel",
				Region:     "us-east-2",
				AccountId:  "123456789012",
				Properties: "{\"ChannelArn\":\"arn:aws:cloudtrail:us-east-2:123456789012:channel/aws-service-channel/resource-explorer-2/47e5a5bc-4359-4556-81bc-9a34cfb4e89c\",\"Name\":\"aws-service-channel/resource-explorer-2/default\"}",
				Arn: arn.ARN{
					Partition: "aws",
					Service:   "cloudtrail",
					Region:    "us-east-2",
					AccountID: "123456789012",
					Resource:  "channel/aws-service-channel/resource-explorer-2/47e5a5bc-4359-4556-81bc-9a34cfb4e89c",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewEnrichedResourceDescription(tt.identifier, tt.typeName, tt.region, tt.accountId, tt.properties)
			assert.Equal(t, tt.expected, result)
		})
	}
}
