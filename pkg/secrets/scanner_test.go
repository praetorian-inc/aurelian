package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startScanner(t *testing.T) *SecretScanner {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "titus.db")
	var s SecretScanner
	require.NoError(t, s.Start(dbPath))
	t.Cleanup(func() { s.Close() })
	return &s
}

func TestSecretScanner_StartAndClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(dbPath))

	assert.Equal(t, dbPath, s.DBPath())
	_, err := os.Stat(dbPath)
	assert.NoError(t, err)

	require.NoError(t, s.Close())
	assert.Empty(t, s.DBPath())
}

func TestSecretScanner_CloseWithoutStart(t *testing.T) {
	var s SecretScanner
	assert.NoError(t, s.Close())
}

func TestSecretScanner_CustomDBPath(t *testing.T) {
	customPath := filepath.Join(t.TempDir(), "sub", "dir", "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(customPath))
	defer s.Close()

	assert.Equal(t, customPath, s.DBPath())
	_, err := os.Stat(customPath)
	assert.NoError(t, err)
}

func TestSecretScanner_ScanPipelineNoSecrets(t *testing.T) {
	s := startScanner(t)

	input := output.ScanInput{
		Content:    []byte("just some regular text"),
		ResourceID: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
		Label:      "readme.txt",
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(input, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestSecretScanner_IncrementalScanning(t *testing.T) {
	s := startScanner(t)

	content := []byte("some content here")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "file.txt"}

	matches1, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)

	// Second scan returns cached results
	matches2, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)
	assert.Equal(t, len(matches1), len(matches2))
}

func TestSecretScanner_DatabasePersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")
	content := []byte("test content for persistence")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test.txt"}

	// First session
	var s1 SecretScanner
	require.NoError(t, s1.Start(dbPath))
	matches1, err := s1.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)
	require.NoError(t, s1.Close())

	_, err = os.Stat(dbPath)
	require.NoError(t, err, "database file should persist after close")

	// Second session — same DB
	var s2 SecretScanner
	require.NoError(t, s2.Start(dbPath))
	defer s2.Close()

	matches2, err := s2.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)
	assert.Equal(t, len(matches1), len(matches2))
}
