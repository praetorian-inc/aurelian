package secrets

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockScanner implements the Scanner interface for testing.
type mockScanner struct {
	matches []*types.Match
	err     error
}

func (m *mockScanner) ScanContent(content []byte, blobID types.BlobID, provenance types.Provenance) ([]*types.Match, error) {
	return m.matches, m.err
}

func TestScanStage_WithMatches(t *testing.T) {
	scanner := &mockScanner{
		matches: []*types.Match{
			{
				RuleID:   "np.aws.1",
				RuleName: "AWS Access Key",
				Snippet: types.Snippet{
					Before:   []byte("export KEY="),
					Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
					After:    []byte("\n"),
				},
				Location: types.Location{
					Source: types.SourceSpan{
						Start: types.SourcePoint{Line: 1, Column: 12},
						End:   types.SourcePoint{Line: 1, Column: 32},
					},
				},
			},
		},
	}

	input := ScanInput{
		Content:      []byte("export KEY=AKIAIOSFODNN7EXAMPLE\n"),
		ResourceID:   "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
		ResourceType: "AWS::EC2::Instance",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Label:        "UserData",
	}

	out := pipeline.New[output.SecretFinding]()
	scanFn := ScanForSecrets(scanner)

	go func() {
		defer out.Close()
		err := scanFn(input, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc", items[0].ResourceRef)
	assert.Equal(t, "np.aws.1", items[0].RuleTextID)
	assert.Equal(t, "AWS Access Key", items[0].RuleName)
	assert.Equal(t, "UserData", items[0].FilePath)
	assert.Equal(t, 1, items[0].LineNumber)
}

func TestScanStage_NoMatches(t *testing.T) {
	scanner := &mockScanner{matches: nil}

	input := ScanInput{
		Content:      []byte("just some regular text\n"),
		ResourceID:   "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
		ResourceType: "AWS::EC2::Instance",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Label:        "UserData",
	}

	out := pipeline.New[output.SecretFinding]()
	scanFn := ScanForSecrets(scanner)

	go func() {
		defer out.Close()
		err := scanFn(input, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
