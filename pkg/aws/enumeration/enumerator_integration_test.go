//go:build integration

package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

func Test_Enumerator_EnumerateByType_UsesReconListFixture(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-2"},
		Concurrency: 2,
	})

	instanceResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::EC2::Instance", out)
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceResults)
	for _, id := range fixture.OutputList("instance_ids") {
		require.True(t, resultsContainResourceID(instanceResults, id), "expected instance id %q in Enumerator output", id)
	}

	bucketResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::S3::Bucket", out)
	})
	require.NoError(t, err)
	require.NotEmpty(t, bucketResults)
	for _, name := range fixture.OutputList("bucket_names") {
		require.True(t, resultsContainResourceID(bucketResults, name), "expected bucket name %q in Enumerator output", name)
	}

	lambdaResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::Lambda::Function", out)
	})
	require.NoError(t, err)
	require.NotEmpty(t, lambdaResults)
	for _, arn := range fixture.OutputList("function_arns") {
		require.True(t, resultsContainARN(lambdaResults, arn), "expected lambda arn %q in Enumerator output", arn)
	}
}

func Test_Enumerator_EnumerateByARN_UsesReconListFixture(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	enumerator := NewEnumerator(plugin.AWSCommonRecon{Concurrency: 1})

	for _, arn := range fixture.OutputList("function_arns") {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List(arn, out)
		})
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, arn, results[0].ARN)
	}
}

func collectResources(run func(out *pipeline.P[output.AWSResource]) error) ([]output.AWSResource, error) {
	out := pipeline.New[output.AWSResource]()

	resultCh := make(chan []output.AWSResource, 1)
	go func() {
		var results []output.AWSResource
		for r := range out.Range() {
			results = append(results, r)
		}
		resultCh <- results
	}()

	err := run(out)
	out.Close()
	results := <-resultCh
	return results, err
}

func resultsContainResourceID(results []output.AWSResource, resourceID string) bool {
	for _, result := range results {
		if result.ResourceID == resourceID {
			return true
		}
	}
	return false
}

func resultsContainARN(results []output.AWSResource, arn string) bool {
	for _, result := range results {
		if result.ARN == arn {
			return true
		}
	}
	return false
}
