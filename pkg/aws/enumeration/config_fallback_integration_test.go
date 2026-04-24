//go:build integration

package enumeration

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_ConfigFallback_DiscoversBucketsViaConfig deploys an S3 bucket and an
// AWS Config recorder that tracks S3 buckets, then invokes ConfigFallback
// directly to verify it discovers the bucket end-to-end (ListDiscoveredResources
// → CloudControl GetResource → pipeline emission).
//
// This test does NOT simulate the SCP denial of s3:ListAllMyBuckets — it
// exercises the ConfigFallback path directly with a real Config recorder.
// Manual verification against the LAB-2525 pilot covers the SCP path.
func Test_ConfigFallback_DiscoversBucketsViaConfig(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/enumeration/config-fallback")
	fixture.Setup()

	opts := plugin.AWSCommonRecon{
		Regions:     []string{fixture.Output("region")},
		Concurrency: 2,
	}
	provider := NewAWSConfigProvider(opts)
	cc := NewCloudControlEnumeratorWithProvider(opts, provider)
	fallback := NewConfigFallback(provider, cc)

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Pre-flight: wait for the recorder's first Success status. Until this
	// fires, discovery has not yet run at all, so polling ListDiscoveredResources
	// will return confusing empties.
	cfgSDK, err := provider.GetAWSConfig(fixture.Output("region"))
	require.NoError(t, err)
	cfgClient := configservice.NewFromConfig(*cfgSDK)
	require.Eventually(t, func() bool {
		resp, err := cfgClient.DescribeConfigurationRecorderStatus(
			context.Background(),
			&configservice.DescribeConfigurationRecorderStatusInput{},
		)
		if err != nil || len(resp.ConfigurationRecordersStatus) == 0 {
			return false
		}
		return aws.ToString(resp.ConfigurationRecordersStatus[0].LastStatus) == "Success"
	}, 5*time.Minute, 15*time.Second, "recorder never reached Success status")

	// Bounded retry on errConfigNoRecords: the recorder can take 10-15 minutes
	// after first Success to populate the baseline snapshot.
	var (
		got     []output.AWSResource
		lastErr error
	)
	const (
		maxAttempts    = 40
		attemptBackoff = 30 * time.Second
	)
	for attempt := range maxAttempts {
		out := pipeline.New[output.AWSResource]()
		done := make(chan []output.AWSResource, 1)
		go func() {
			var collected []output.AWSResource
			for r := range out.Range() {
				collected = append(collected, r)
			}
			done <- collected
		}()

		lastErr = fallback.Attempt(context.Background(), "AWS::S3::Bucket", fixture.Output("region"), out)
		out.Close()
		require.NoError(t, out.Wait())
		got = <-done
		if lastErr == nil {
			break
		}
		if !errors.Is(lastErr, errConfigNoRecords) {
			break
		}
		if attempt == maxAttempts-1 {
			break
		}
		t.Logf("recorder not yet populated (attempt %d/%d); retrying in %s", attempt+1, maxAttempts, attemptBackoff)
		time.Sleep(attemptBackoff)
	}

	require.NoError(t, lastErr, "fallback must eventually succeed (recorder baseline takes ~10-15min on cold start)")

	wantBucket := fixture.Output("target_bucket_name")

	found := false
	for _, r := range got {
		if r.ResourceID == wantBucket {
			found = true
			break
		}
	}
	assert.True(t, found, "expected target bucket %q in fallback output; got %d resources", wantBucket, len(got))

	logs := logBuf.String()
	assert.NotContains(t, logs, "config recorder unavailable in region",
		"must not log recorder-unavailable when recorder is recording")
	assert.NotContains(t, logs, "cloudcontrol get denied in region",
		"must not log hydration-blocked on happy path")
	// Expect the success debug line somewhere in the run.
	assert.Contains(t, strings.ToLower(logs), "fell back to config")
}
