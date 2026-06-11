//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bucketAlreadyGone reports whether an S3 error means the bucket no longer
// exists. When the fixture is reused across runs the vulnerable bucket has
// already been deleted, which is precisely the takeover condition we want, so
// the mutation helper must treat this as success rather than a failure.
func bucketAlreadyGone(err error) bool {
	if err == nil {
		return false
	}
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return true
	}
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	es := err.Error()
	return strings.Contains(es, "NoSuchBucket") ||
		strings.Contains(es, "NotFound") ||
		strings.Contains(es, "StatusCode: 404") ||
		strings.Contains(es, "404")
}

// validTriageStatuses are the triage codes the takeover risk may legitimately
// carry (medium / high / critical depending on the affected-domain context).
var validTriageStatuses = map[string]bool{"TM": true, "TH": true, "TC": true}

// deleteBucket empties and deletes an S3 bucket so the CloudFront distribution
// origin becomes a missing bucket (the vulnerable condition the module detects).
// This mutation cannot be expressed in Terraform desired state, so it runs after
// fixture provisioning. Failures are surfaced via require.
func deleteBucket(t *testing.T, bucketName string) {
	t.Helper()
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	require.NoError(t, err, "load aws config for bucket deletion")
	client := s3.NewFromConfig(cfg)

	// The fixture is reused across runs (hash-based redeploy). On a reused
	// fixture the vulnerable bucket is already gone, which IS the takeover
	// condition we want, so an "already absent" bucket is treated as success.
	listOut, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucketName})
	if bucketAlreadyGone(err) {
		t.Logf("vulnerable origin bucket %s already absent; takeover condition present", bucketName)
		return
	}
	require.NoError(t, err, "list objects in bucket %s", bucketName)
	for _, obj := range listOut.Contents {
		_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucketName, Key: obj.Key})
		require.NoError(t, err, "delete object %s from bucket %s", *obj.Key, bucketName)
	}

	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucketName})
	if bucketAlreadyGone(err) {
		t.Logf("vulnerable origin bucket %s already absent; takeover condition present", bucketName)
		return
	}
	require.NoError(t, err, "delete bucket %s", bucketName)
	t.Logf("deleted vulnerable origin bucket %s to create the takeover condition", bucketName)
}

// decodeProof unmarshals a Risk's proof bytes into a structured capmodel.Proof.
func decodeProof(t *testing.T, risk capmodel.Risk) capmodel.Proof {
	t.Helper()
	var proof capmodel.Proof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof), "proof should decode into capmodel.Proof")
	return proof
}

// sectionByTitle returns the named proof section, failing if it is absent.
func sectionByTitle(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	for _, s := range proof.Sections {
		if s.Title == title {
			return s
		}
	}
	require.Failf(t, "section not found", "proof has no %q section", title)
	return capmodel.ProofSection{}
}

// keyValueMap flattens a section's key/value rows into a map for assertions.
func keyValueMap(section capmodel.ProofSection) map[string]string {
	out := make(map[string]string)
	for _, el := range section.Elements {
		if el.KeyValue == nil {
			continue
		}
		for _, row := range el.KeyValue.Rows {
			out[row.Key] = row.Value
		}
	}
	return out
}

// listLabels collects the labels of every list item across a section.
func listLabels(section capmodel.ProofSection) []string {
	var labels []string
	for _, el := range section.Elements {
		if el.List == nil {
			continue
		}
		for _, item := range el.List.Items {
			labels = append(labels, item.Label)
		}
	}
	return labels
}

// paragraphText concatenates the text of every paragraph element in a section.
func paragraphText(section capmodel.ProofSection) string {
	var text string
	for _, el := range section.Elements {
		if el.Paragraph != nil {
			text += el.Paragraph.Text
		}
	}
	return text
}

// distributionID pulls the "Distribution ID" key-value out of a risk's proof.
func distributionID(t *testing.T, risk capmodel.Risk) string {
	t.Helper()
	proof := decodeProof(t, risk)
	return keyValueMap(sectionByTitle(t, proof, "Distribution Details"))["Distribution ID"]
}

// TestAWSCloudFrontS3Takeover verifies the LAB-3995 migration: the module emits
// a platform capmodel.Risk (not the legacy output.AurelianRisk) with a
// structured capmodel.Proof. It provisions the cloudfront-s3-takeover fixture,
// deletes the vulnerable distribution's origin bucket mid-test to create the
// takeover condition, runs the module, and asserts the new contract.
func TestAWSCloudFrontS3Takeover(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/cloudfront-s3-takeover")
	fixture.Setup()

	vulnDistID := fixture.Output("vulnerable_distribution_id")
	vulnBucket := fixture.Output("vulnerable_bucket_name")
	healthyDistID := fixture.Output("healthy_distribution_id")
	healthyBucket := fixture.Output("healthy_bucket_name")

	// Mid-test mutation: delete the vulnerable origin bucket so the distribution
	// references a non-existent bucket. The healthy bucket is left intact.
	deleteBucket(t, vulnBucket)

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "cloudfront-s3-takeover")
	if !ok {
		t.Fatal("cloudfront-s3-takeover module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	// Collect emitted models; the migrated module emits capmodel.Risk values.
	var risks []capmodel.Risk
	for m := range p2.Range() {
		if r, ok := m.(capmodel.Risk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one emitted capmodel.Risk")

	// Locate the risk for our vulnerable distribution by matching the proof's
	// Distribution ID (the module scans every distribution in the account).
	var vulnRisk *capmodel.Risk
	for i := range risks {
		if distributionID(t, risks[i]) == vulnDistID {
			vulnRisk = &risks[i]
			break
		}
	}
	require.NotNilf(t, vulnRisk, "expected a capmodel.Risk for vulnerable distribution %s", vulnDistID)

	t.Run("emitted item is a capmodel.Risk with the migrated contract", func(t *testing.T) {
		assert.Equal(t, "CloudFront S3 Origin Takeover", vulnRisk.Name)
		assert.Equal(t, "aurelian", vulnRisk.Source)
		assert.Truef(t, validTriageStatuses[vulnRisk.Status],
			"Status %q should be a valid triage code (TM/TH/TC)", vulnRisk.Status)
		assert.NotEmpty(t, vulnRisk.TargetName, "TargetName should be non-empty")
	})

	t.Run("status is TM (no Route53 records or aliases in fixture)", func(t *testing.T) {
		assert.Equal(t, "TM", vulnRisk.Status,
			"missing bucket with no affected domains maps to Medium -> TM")
	})

	t.Run("proof decodes to a structured capmodel.Proof", func(t *testing.T) {
		proof := decodeProof(t, *vulnRisk)
		// Assert the proof Format matches what the module actually emits.
		// The migrated code sets Format = "v1.0.0"; keep in lockstep with risk.go.
		assert.Equal(t, "v1.0.0", proof.Format)
		assert.NotEmpty(t, proof.Sections, "proof should carry sections")
	})

	t.Run("proof Distribution Details carry the distribution and missing bucket", func(t *testing.T) {
		proof := decodeProof(t, *vulnRisk)
		kv := keyValueMap(sectionByTitle(t, proof, "Distribution Details"))
		assert.Equal(t, vulnDistID, kv["Distribution ID"])
		assert.NotEmpty(t, kv["Distribution Domain"], "Distribution Domain should be present")
		assert.Contains(t, kv["Distribution Domain"], "cloudfront.net",
			"Distribution Domain should be the CloudFront domain")
		assert.Equal(t, vulnBucket, kv["Missing Bucket"],
			"Missing Bucket should be the deleted origin bucket")
	})

	t.Run("TargetName falls back to the distribution domain", func(t *testing.T) {
		proof := decodeProof(t, *vulnRisk)
		domain := keyValueMap(sectionByTitle(t, proof, "Distribution Details"))["Distribution Domain"]
		assert.Equal(t, domain, vulnRisk.TargetName,
			"with no affected domains TargetName should equal the distribution domain")
	})

	t.Run("proof carries description and recommendation evidence", func(t *testing.T) {
		proof := decodeProof(t, *vulnRisk)
		summary := paragraphText(sectionByTitle(t, proof, "Summary"))
		assert.NotEmpty(t, summary, "Summary paragraph (description) should be present")
		assert.Contains(t, summary, vulnBucket, "description should name the missing bucket")

		assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Impact")),
			"Impact paragraph should be present")
		assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "Recommendation")),
			"Recommendation list should be present")
		assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "References")),
			"References list should be present")
	})

	t.Run("FP1: healthy distribution is not flagged", func(t *testing.T) {
		for i := range risks {
			assert.NotEqualf(t, healthyDistID, distributionID(t, risks[i]),
				"healthy distribution %s must not be flagged", healthyDistID)
		}
	})

	t.Run("FP2: healthy origin bucket never appears as a missing bucket", func(t *testing.T) {
		for i := range risks {
			proof := decodeProof(t, risks[i])
			kv := keyValueMap(sectionByTitle(t, proof, "Distribution Details"))
			assert.NotEqualf(t, healthyBucket, kv["Missing Bucket"],
				"healthy bucket %s must never be reported as a missing bucket", healthyBucket)
		}
	})

	t.Run("all emitted risks satisfy the capmodel contract", func(t *testing.T) {
		for i := range risks {
			assert.Equal(t, "CloudFront S3 Origin Takeover", risks[i].Name)
			assert.Equal(t, "aurelian", risks[i].Source)
			assert.Truef(t, validTriageStatuses[risks[i].Status],
				"Status %q should be a valid triage code", risks[i].Status)
			assert.NotEmpty(t, risks[i].TargetName, "TargetName should be non-empty")
			assert.NotEmpty(t, risks[i].Proof, "Proof should be non-empty")
		}
	})
}
