//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
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
	fixture := testutil.NewAWSFixture(t, "aws/recon/cloudfront-s3-takeover")
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

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	// Extract risks from results
	var risks []output.AurelianRisk
	for _, r := range results {
		if risk, ok := r.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}

	t.Run("detects missing bucket", func(t *testing.T) {
		found := false
		for _, risk := range risks {
			if risk.ImpactedResourceID == vulnDistID {
				found = true
				assert.Equal(t, "cloudfront-s3-takeover", risk.Name)
				assert.Contains(t, []output.RiskSeverity{output.RiskSeverityMedium, output.RiskSeverityHigh}, risk.Severity)

				var ctx map[string]any
				require.NoError(t, json.Unmarshal(risk.Context, &ctx))
				assert.Equal(t, vulnBucket, ctx["missing_bucket"])
			}
		}
		assert.True(t, found, "expected risk for vulnerable distribution %s", vulnDistID)
	})

	t.Run("does not flag healthy distribution", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEqual(t, healthyDistID, risk.ImpactedResourceID,
				"healthy distribution %s should not produce a risk", healthyDistID)
		}
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
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucket") {
			t.Logf("bucket %s already deleted, skipping", bucketName)
			return
		}
		require.NoError(t, err, "failed to delete bucket %s", bucketName)
	}
	t.Logf("deleted S3 bucket %s to simulate takeover vulnerability", bucketName)
}
