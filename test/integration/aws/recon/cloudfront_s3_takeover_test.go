//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSCloudFrontS3Takeover(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/cloudfront-s3-takeover")
	fixture.Setup()

	vulnBucket := fixture.Output("vulnerable_bucket_name")
	vulnDistID := fixture.Output("vulnerable_distribution_id")
	healthyDistID := fixture.Output("healthy_distribution_id")

	// Delete the vulnerable bucket to simulate the takeover condition
	deleteBucket(t, vulnBucket)

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "cloudfront-s3-takeover")
	if !ok {
		t.Fatal("cloudfront-s3-takeover module not registered")
	}

	results, err := mod.Run(plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 1)

	// Extract risks from results
	var risks []output.Risk
	for _, r := range results {
		if riskSlice, ok := r.Data.([]output.Risk); ok {
			risks = append(risks, riskSlice...)
		}
	}

	t.Run("detects missing bucket", func(t *testing.T) {
		found := false
		for _, risk := range risks {
			if risk.DNS == vulnDistID {
				found = true
				assert.Equal(t, "cloudfront-s3-takeover", risk.Name)
				assert.Contains(t, []string{"TM", "TH"}, risk.Status)
				assert.Equal(t, "aurelian-cloudfront-scanner", risk.Source)
				assert.Contains(t, risk.Description, vulnBucket)
			}
		}
		assert.True(t, found, "expected risk for vulnerable distribution %s", vulnDistID)
	})

	t.Run("does not flag healthy distribution", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEqual(t, healthyDistID, risk.DNS,
				"healthy distribution %s should not produce a risk", healthyDistID)
		}
	})

	t.Run("result metadata contains expected fields", func(t *testing.T) {
		require.GreaterOrEqual(t, len(results), 1)
		meta := results[0].Metadata
		assert.Equal(t, "cloudfront-s3-takeover", meta["module"])
		assert.Equal(t, "aws", meta["platform"])
		assert.NotEmpty(t, meta["accountID"])
	})
}

// deleteBucket empties and deletes an S3 bucket.
func deleteBucket(t *testing.T, bucketName string) {
	t.Helper()
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	require.NoError(t, err)

	client := s3.NewFromConfig(cfg)

	// List and delete all objects first
	listOut, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: &bucketName,
	})
	if err == nil {
		for _, obj := range listOut.Contents {
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucketName,
				Key:    obj.Key,
			})
		}
	}

	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucketName,
	})
	require.NoError(t, err, "failed to delete bucket %s", bucketName)
	t.Logf("deleted S3 bucket %s to simulate takeover vulnerability", bucketName)
}
