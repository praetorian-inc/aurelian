//go:build integration

package resourcepolicies

import (
	"context"
	"encoding/json"
	"testing"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
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
				Platform:     "aws",
				ResourceType: "AWS::S3::Bucket",
				ResourceID:   s3BucketName,
				ARN:          s3BucketARN,
				Region:       region,
				Properties:   map[string]any{"BucketName": s3BucketName},
			},
			{
				Platform:     "aws",
				ResourceType: "AWS::SQS::Queue",
				ResourceID:   sqsQueueARN,
				ARN:          sqsQueueARN,
				Region:       region,
				Properties:   map[string]any{"QueueUrl": sqsQueueURL},
			},
			{
				Platform:     "aws",
				ResourceType: "AWS::SNS::Topic",
				ResourceID:   snsTopicARN,
				ARN:          snsTopicARN,
				Region:       region,
				Properties:   map[string]any{"TopicArn": snsTopicARN},
			},
			{
				Platform:     "aws",
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
				Platform:     "aws",
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

	t.Run("matches legacy CollectPolicies", func(t *testing.T) {
		// Build an aws.Config for the legacy function (it takes one config per region).
		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region: region,
		})
		require.NoError(t, err)

		// Flatten region-keyed map into the flat slice that CollectPolicies expects.
		var flat []output.AWSResource
		for _, resources := range resourcesByRegion {
			flat = append(flat, resources...)
		}

		legacyResults, err := CollectPolicies(context.Background(), awsCfg, flat)
		require.NoError(t, err)

		require.NotEmpty(t, results, "new collector results should not be empty")
		require.NotEmpty(t, legacyResults, "legacy CollectPolicies results should not be empty")

		// Compare by ARN set.
		newARNs := make(map[string]bool)
		for _, r := range results {
			newARNs[r.ARN] = true
		}
		legacyARNs := make(map[string]bool)
		for _, r := range legacyResults {
			legacyARNs[r.ARN] = true
		}
		assert.Equal(t, legacyARNs, newARNs, "resource ARN sets should match")

		// Compare policies per ARN: legacy stores JSON in Properties, new uses typed field.
		legacyByARN := make(map[string]*types.Policy)
		for _, r := range legacyResults {
			policyJSON, ok := r.Properties["ResourcePolicy"].(string)
			require.True(t, ok, "legacy result for %s should have ResourcePolicy string", r.ARN)
			var policy types.Policy
			require.NoError(t, json.Unmarshal([]byte(policyJSON), &policy))
			legacyByARN[r.ARN] = &policy
		}

		newByARN := make(map[string]*types.Policy)
		for _, r := range results {
			require.NotNil(t, r.ResourcePolicy, "new result for %s should have typed ResourcePolicy", r.ARN)
			newByARN[r.ARN] = r.ResourcePolicy
		}

		for arn, legacyPolicy := range legacyByARN {
			newPolicy, ok := newByARN[arn]
			require.True(t, ok, "new results should contain ARN %s", arn)

			assert.Equal(t, legacyPolicy.Version, newPolicy.Version,
				"policy version mismatch for %s", arn)
			require.NotNil(t, legacyPolicy.Statement, "legacy policy for %s should have statements", arn)
			require.NotNil(t, newPolicy.Statement, "new policy for %s should have statements", arn)
			assert.Equal(t, len(*legacyPolicy.Statement), len(*newPolicy.Statement),
				"statement count mismatch for %s", arn)
		}
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
