package types

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/stretchr/testify/assert"
)

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
				Identifier: "https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue",
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
