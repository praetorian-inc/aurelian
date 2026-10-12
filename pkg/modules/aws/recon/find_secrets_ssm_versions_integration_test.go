//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSSMTestClient(t *testing.T, region string) *ssm.Client {
	t.Helper()
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	require.NoError(t, err, "load AWS config")
	return ssm.NewFromConfig(cfg)
}

// TestAWSFindSecretsSSMDocumentVersions uses the find-secrets fixture's
// versioned document, whose default version (1) is clean and whose newer
// version (2) holds a secret, and checks that list-all stamps LastModified from
// $LATEST while still describing the default, and that find-secrets attributes
// the secret to version 2 only.
func TestAWSFindSecretsSSMDocumentVersions(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	const region = lastModifiedTestRegion
	docName := fixture.Output("ssm_versioned_document_name")
	docARN := fixture.Output("ssm_versioned_document_arn")
	require.NotEmpty(t, docName, "fixture output ssm_versioned_document_name")
	require.NotEmpty(t, docARN, "fixture output ssm_versioned_document_arn")

	// Read-only: the expected LastModified is the $LATEST (v2) CreatedDate.
	resp, err := newSSMTestClient(t, region).DescribeDocument(context.Background(), &ssm.DescribeDocumentInput{
		Name:            aws.String(docName),
		DocumentVersion: aws.String("$LATEST"),
	})
	require.NoError(t, err, "DescribeDocument %s@$LATEST", docName)
	latest := resp.Document
	require.Equal(t, "1", aws.ToString(latest.DefaultVersion),
		"fixture malformed: %s default version must be 1 (clean)", docName)
	require.Equal(t, "2", aws.ToString(latest.LatestVersion),
		"fixture malformed: %s latest version must be 2 (secret, non-default)", docName)
	require.NotNil(t, latest.CreatedDate, "fixture malformed: %s $LATEST has no CreatedDate", docName)

	t.Run("list-all stamps $LATEST CreatedDate and describes the default", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		require.True(t, ok, "list-all module not registered in plugin system")

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::SSM::Document"},
				"regions":       []string{region},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		var found []output.AWSResource
		for _, r := range awsResources(results) {
			if r.ResourceID == docName {
				found = append(found, r)
			}
		}
		require.Len(t, found, 1, "expected exactly one listed document %s", docName)
		r := found[0]
		assert.Equal(t, docARN, r.ARN, "listed ARN must match the fixture output")

		require.NotNil(t, r.LastModified, "document must carry LastModified")
		assert.True(t, latest.CreatedDate.Equal(*r.LastModified),
			"LastModified %s must equal $LATEST (v2) CreatedDate %s", r.LastModified, latest.CreatedDate)
		assert.Equal(t, "1", r.Properties["DocumentVersion"], "Properties describe the default version")
	})

	t.Run("find-secrets attributes the secret to version 2 only", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
		require.True(t, ok, "find-secrets module not registered in plugin system")

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"regions":       []string{region},
				"resource-type": []string{"AWS::SSM::Document"},
				"db-path":       filepath.Join(t.TempDir(), "titus.db"),
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		var v2Risks int
		for _, m := range results {
			risk, ok := m.(output.AurelianRisk)
			if !ok {
				continue
			}
			assert.NotContains(t, risk.ImpactedResourceID, docARN+":1:", "clean version 1 must yield no risk")
			if !strings.Contains(risk.ImpactedResourceID, docARN+":2:") {
				continue
			}
			v2Risks++
			t.Logf("risk %s on %s", risk.Name, risk.ImpactedResourceID)

			var proof struct {
				Matches []struct {
					Provenance []struct {
						Subresource string `json:"subresource"`
					} `json:"provenance"`
				} `json:"matches"`
			}
			require.NoError(t, json.Unmarshal(risk.Context, &proof))
			require.NotEmpty(t, proof.Matches)
			require.NotEmpty(t, proof.Matches[0].Provenance)
			assert.Equal(t, "Document version 2", proof.Matches[0].Provenance[0].Subresource)
		}
		assert.Positive(t, v2Risks, "expected at least one risk on %s:2", docARN)
	})
}
