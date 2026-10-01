//go:build integration

package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ssmVersionDocContent renders a Command document whose runCommand is lines.
func ssmVersionDocContent(t *testing.T, lines ...string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schemaVersion": "2.2",
		"description":   "aurelian integration test: per-version secret scanning",
		"mainSteps": []map[string]any{{
			"action": "aws:runShellScript",
			"name":   "run",
			"inputs": map[string]any{"runCommand": lines},
		}},
	})
	require.NoError(t, err)
	return string(b)
}

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

// waitSSMDocumentVersionActive polls until the given version is Active.
func waitSSMDocumentVersionActive(t *testing.T, client *ssm.Client, name, version string) *ssmtypes.DocumentDescription {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		resp, err := client.DescribeDocument(context.Background(), &ssm.DescribeDocumentInput{
			Name:            aws.String(name),
			DocumentVersion: aws.String(version),
		})
		require.NoError(t, err, "DescribeDocument %s@%s", name, version)
		switch resp.Document.Status {
		case ssmtypes.DocumentStatusActive:
			return resp.Document
		case ssmtypes.DocumentStatusFailed:
			t.Fatalf("document %s@%s failed: %s", name, version, aws.ToString(resp.Document.StatusInformation))
		}
		if time.Now().After(deadline) {
			t.Fatalf("document %s@%s not Active after 2m (status %s)", name, version, resp.Document.Status)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestAWSFindSecretsSSMDocumentVersions creates a document whose default
// version (1) is clean and whose newer version (2) holds a secret, then checks
// that list-all stamps LastModified from $LATEST while still describing the
// default, and that find-secrets attributes the secret to version 2 only.
func TestAWSFindSecretsSSMDocumentVersions(t *testing.T) {
	const region = lastModifiedTestRegion
	client := newSSMTestClient(t, region)

	suffix := make([]byte, 4)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	docName := "aurelian-it-ssmver-" + hex.EncodeToString(suffix)

	_, err = client.CreateDocument(context.Background(), &ssm.CreateDocumentInput{
		Name:           aws.String(docName),
		DocumentType:   ssmtypes.DocumentTypeCommand,
		DocumentFormat: ssmtypes.DocumentFormatJson,
		Content:        aws.String(ssmVersionDocContent(t, "echo clean")),
	})
	require.NoError(t, err, "CreateDocument")
	t.Cleanup(func() {
		if _, err := client.DeleteDocument(context.Background(), &ssm.DeleteDocumentInput{Name: aws.String(docName)}); err != nil {
			t.Logf("cleanup: DeleteDocument %s: %v", docName, err)
		}
	})
	waitSSMDocumentVersionActive(t, client, docName, "1")

	// Intentionally fake credentials, the same pair the find-secrets fixture uses.
	_, err = client.UpdateDocument(context.Background(), &ssm.UpdateDocumentInput{
		Name:            aws.String(docName),
		DocumentVersion: aws.String("$LATEST"),
		DocumentFormat:  ssmtypes.DocumentFormatJson,
		Content: aws.String(ssmVersionDocContent(t,
			"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		)),
	})
	require.NoError(t, err, "UpdateDocument")
	latest := waitSSMDocumentVersionActive(t, client, docName, "$LATEST")
	require.Equal(t, "2", aws.ToString(latest.DocumentVersion))
	require.Equal(t, "1", aws.ToString(latest.DefaultVersion), "default must stay at version 1")
	require.NotNil(t, latest.CreatedDate)

	var docARN string
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
		docARN = r.ARN

		require.NotNil(t, r.LastModified, "document must carry LastModified")
		assert.True(t, latest.CreatedDate.Equal(*r.LastModified),
			"LastModified %s must equal $LATEST (v2) CreatedDate %s", r.LastModified, latest.CreatedDate)
		assert.Equal(t, "1", r.Properties["DocumentVersion"], "Properties describe the default version")
	})
	require.NotEmpty(t, docARN, "list-all must resolve the document ARN")

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
