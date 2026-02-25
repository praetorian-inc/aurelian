//go:build integration

package resourcepolicies

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourcePolicyCollector_Integration(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	region := "us-east-2"

	// Build resource inputs directly from terraform outputs.
	// No GAAD or CloudControl calls needed.
	s3BucketName := fixture.Output("s3_bucket_name")
	s3BucketARN := fixture.Output("s3_bucket_arn")
	sqsQueueURL := fixture.Output("sqs_queue_url")
	sqsQueueARN := fixture.Output("sqs_queue_arn")
	snsTopicARN := fixture.Output("sns_topic_arn")
	lambdaFunctionName := fixture.Output("lambda_function_name")
	lambdaFunctionARN := fixture.Output("lambda_function_arn")

	resourcesByRegion := map[string][]output.AWSResource{
		region: {
			{
				ResourceType: "AWS::S3::Bucket",
				ResourceID:   s3BucketName,
				ARN:          s3BucketARN,
				Region:       region,
				Properties:   map[string]any{"BucketName": s3BucketName},
			},
			{
				ResourceType: "AWS::SQS::Queue",
				ResourceID:   sqsQueueARN,
				ARN:          sqsQueueARN,
				Region:       region,
				Properties:   map[string]any{"QueueUrl": sqsQueueURL},
			},
			{
				ResourceType: "AWS::SNS::Topic",
				ResourceID:   snsTopicARN,
				ARN:          snsTopicARN,
				Region:       region,
				Properties:   map[string]any{"TopicArn": snsTopicARN},
			},
			{
				ResourceType: "AWS::Lambda::Function",
				ResourceID:   lambdaFunctionARN,
				ARN:          lambdaFunctionARN,
				Region:       region,
				Properties:   map[string]any{"FunctionName": lambdaFunctionName},
			},
		},
	}

	collector := New(plugin.AWSCommonRecon{})
	results, err := collector.Collect(resourcesByRegion)
	require.NoError(t, err)

	// Index results by resource type.
	byType := make(map[string]output.AWSResource)
	for _, r := range results {
		byType[r.ResourceType] = r
	}

	t.Run("all 4 resource types returned", func(t *testing.T) {
		assert.Len(t, results, 4, "expected policies for S3, SQS, SNS, and Lambda")
	})

	t.Run("S3 bucket policy collected", func(t *testing.T) {
		r, ok := byType["AWS::S3::Bucket"]
		require.True(t, ok, "S3 bucket should have a policy")
		requireValidPolicy(t, r)
	})

	t.Run("SQS queue policy collected", func(t *testing.T) {
		r, ok := byType["AWS::SQS::Queue"]
		require.True(t, ok, "SQS queue should have a policy")
		requireValidPolicy(t, r)
	})

	t.Run("SNS topic policy collected", func(t *testing.T) {
		r, ok := byType["AWS::SNS::Topic"]
		require.True(t, ok, "SNS topic should have a policy")
		requireValidPolicy(t, r)
	})

	t.Run("Lambda function policy collected", func(t *testing.T) {
		r, ok := byType["AWS::Lambda::Function"]
		require.True(t, ok, "Lambda function should have a policy")
		requireValidPolicy(t, r)
	})

	t.Run("unsupported resource types are skipped", func(t *testing.T) {
		// Add an EC2 instance (unsupported) alongside the real resources.
		mixed := map[string][]output.AWSResource{
			region: append(resourcesByRegion[region], output.AWSResource{
				ResourceType: "AWS::EC2::Instance",
				ResourceID:   "i-fake",
				ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-fake",
				Region:       region,
				Properties:   map[string]any{},
			}),
		}

		mixedResults, err := collector.Collect(mixed)
		require.NoError(t, err)
		// Should still get exactly 4 — the EC2 instance is skipped.
		assert.Len(t, mixedResults, 4)
	})

	t.Run("result ARNs match input ARNs", func(t *testing.T) {
		resultARNs := make(map[string]bool)
		for _, r := range results {
			resultARNs[r.ARN] = true
		}
		assert.True(t, resultARNs[s3BucketARN], "S3 ARN should be in results")
		assert.True(t, resultARNs[sqsQueueARN], "SQS ARN should be in results")
		assert.True(t, resultARNs[snsTopicARN], "SNS ARN should be in results")
		assert.True(t, resultARNs[lambdaFunctionARN], "Lambda ARN should be in results")
	})
}

// requireValidPolicy asserts that a resource has a non-nil typed ResourcePolicy
// with a valid version and at least one statement.
func requireValidPolicy(t *testing.T, r output.AWSResource) {
	t.Helper()
	require.NotNil(t, r.ResourcePolicy, "resource %s should have ResourcePolicy set", r.ResourceID)
	assert.Equal(t, "2012-10-17", r.ResourcePolicy.Version)
	require.NotNil(t, r.ResourcePolicy.Statement)
	assert.NotEmpty(t, *r.ResourcePolicy.Statement)
}
