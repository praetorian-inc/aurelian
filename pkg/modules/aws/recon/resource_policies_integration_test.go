//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSResourcePolicies(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "resource-policies")
	if !ok {
		t.Fatal("resource-policies module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.Len(t, results, 1, "resource-policies module should return exactly 1 result")

	result := results[0]
	resources, ok := result.Data.([]output.AWSResource)
	require.True(t, ok, "result data should be []output.AWSResource, got %T", result.Data)

	// Index results by resource type.
	byType := make(map[string]output.AWSResource)
	for _, r := range resources {
		byType[r.ResourceType] = r
	}

	// Fixture outputs for validation.
	s3BucketARN := fixture.Output("s3_bucket_arn")
	sqsQueueARN := fixture.Output("sqs_queue_arn")
	snsTopicARN := fixture.Output("sns_topic_arn")
	lambdaFunctionARN := fixture.Output("lambda_function_arn")

	t.Run("all 4 resource types returned", func(t *testing.T) {
		assert.GreaterOrEqual(t, len(resources), 4, "expected policies for at least S3, SQS, SNS, and Lambda")
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

	t.Run("result ARNs match fixture ARNs", func(t *testing.T) {
		resultARNs := make(map[string]bool)
		for _, r := range resources {
			resultARNs[r.ARN] = true
		}
		assert.True(t, resultARNs[s3BucketARN], "S3 ARN should be in results")
		assert.True(t, resultARNs[sqsQueueARN], "SQS ARN should be in results")
		assert.True(t, resultARNs[snsTopicARN], "SNS ARN should be in results")
		assert.True(t, resultARNs[lambdaFunctionARN], "Lambda ARN should be in results")
	})

	t.Run("result metadata is correct", func(t *testing.T) {
		assert.Equal(t, "resource-policies", result.Metadata["module"])
		assert.Equal(t, plugin.PlatformAWS, result.Metadata["platform"])

		count, ok := result.Metadata["count"].(int)
		if ok {
			assert.Greater(t, count, 0, "count should be positive")
			assert.Equal(t, len(resources), count, "count metadata should match actual result length")
		}
	})
}

// requireValidPolicy asserts that a resource has a non-nil typed ResourcePolicy
// with a valid version and at least one statement.
func requireValidPolicy(t *testing.T, r output.AWSResource) {
	t.Helper()
	require.NotNil(t, r.ResourcePolicy, "resource %s should have ResourcePolicy set", r.ResourceID)
	assert.Contains(t, []string{"2008-10-17", "2012-10-17"}, r.ResourcePolicy.Version, "policy version should be a valid IAM policy version")
	require.NotNil(t, r.ResourcePolicy.Statement)
	assert.NotEmpty(t, *r.ResourcePolicy.Statement)
}
