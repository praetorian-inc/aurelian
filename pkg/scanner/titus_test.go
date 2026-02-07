package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPersistentScanner(t *testing.T) {
	// Ensure clean test environment
	dbPath := "aurelian-output/titus.db"
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	require.NotNil(t, scanner, "scanner should not be nil")
	defer scanner.Close()

	// Verify database was created
	assert.Equal(t, dbPath, scanner.DBPath(), "DBPath should return correct path")
	_, err = os.Stat(dbPath)
	assert.NoError(t, err, "database file should exist")
}

func TestPersistentScanner_ScanContent(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	defer scanner.Close()

	// Test content with a potential secret
	content := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{
		FilePath: "test/credentials.txt",
	}

	// First scan - should detect and store
	matches, err := scanner.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent should succeed")
	assert.NotNil(t, matches, "matches should not be nil")

	// Second scan - should return cached results (incremental scanning)
	cachedMatches, err := scanner.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent should succeed on second scan")
	assert.NotNil(t, cachedMatches, "cached matches should not be nil")
	assert.Equal(t, len(matches), len(cachedMatches), "cached matches should have same count")
}

func TestPersistentScanner_IncrementalScanning(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	defer scanner.Close()

	content1 := []byte("some content here")
	blobID1 := types.ComputeBlobID(content1)
	provenance1 := types.FileProvenance{FilePath: "file1.txt"}

	content2 := []byte("different content")
	blobID2 := types.ComputeBlobID(content2)
	provenance2 := types.FileProvenance{FilePath: "file2.txt"}

	// Scan first blob
	_, err = scanner.ScanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "first scan should succeed")

	// Scan second blob
	_, err = scanner.ScanContent(content2, blobID2, provenance2)
	require.NoError(t, err, "second scan should succeed")

	// Re-scan first blob (should skip scanning)
	_, err = scanner.ScanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "re-scan should succeed")
}

func TestPersistentScanner_DatabasePersistence(t *testing.T) {
	// Ensure clean test environment
	dbPath := "aurelian-output/titus.db"
	defer os.RemoveAll("aurelian-output")

	content := []byte("test content")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test.txt"}

	// Create scanner and scan content
	scanner1, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")

	initialMatches, err := scanner1.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent should succeed")

	// Close first scanner
	err = scanner1.Close()
	require.NoError(t, err, "Close should succeed")

	// Verify database file still exists
	_, err = os.Stat(dbPath)
	require.NoError(t, err, "database file should persist after close")

	// Create new scanner with same database
	scanner2, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed with existing db")
	defer scanner2.Close()

	// Scan same content - should find it already exists
	cachedMatches, err := scanner2.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent with existing blob should succeed")
	assert.Equal(t, len(initialMatches), len(cachedMatches), "cached matches should have same count as initial scan")
}

func TestPersistentScanner_OutputDirectory(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	defer scanner.Close()

	// Verify output directory was created
	_, err = os.Stat("aurelian-output")
	require.NoError(t, err, "aurelian-output directory should exist")

	// Verify database is in correct location
	expectedPath := filepath.Join("aurelian-output", "titus.db")
	assert.Equal(t, expectedPath, scanner.DBPath(), "database should be in aurelian-output")
}

func TestPersistentScanner_Close(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")

	// Close should succeed
	err = scanner.Close()
	assert.NoError(t, err, "Close should succeed")

	// Multiple closes should not panic (though may return error)
	_ = scanner.Close()
}

func TestPersistentScanner_FindingsCreation(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	defer scanner.Close()

	// Test content with a potential secret (AWS Access Key)
	content := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{
		FilePath: "test/credentials.txt",
	}

	// Scan content - should detect and store matches
	matches, err := scanner.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent should succeed")
	require.NotEmpty(t, matches, "should detect at least one match")

	// Verify findings were created in the database
	findings, err := scanner.store.GetFindings()
	require.NoError(t, err, "GetFindings should succeed")
	assert.NotEmpty(t, findings, "should have created at least one finding")

	// Verify finding has correct structure
	for _, finding := range findings {
		assert.NotEmpty(t, finding.ID, "finding should have ID")
		assert.NotEmpty(t, finding.RuleID, "finding should have RuleID")
		assert.NotNil(t, finding.Groups, "finding should have Groups")
	}
}

func TestPersistentScanner_FindingsDeduplication(t *testing.T) {
	// Ensure clean test environment
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner should succeed")
	defer scanner.Close()

	// Same secret in two different files (different blobs)
	content1 := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
	blobID1 := types.ComputeBlobID(content1)
	provenance1 := types.FileProvenance{FilePath: "file1/credentials.txt"}

	content2 := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
	blobID2 := types.ComputeBlobID(content2)
	provenance2 := types.FileProvenance{FilePath: "file2/credentials.txt"}

	// Scan first blob
	matches1, err := scanner.ScanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "first scan should succeed")
	require.NotEmpty(t, matches1, "should detect matches in first file")

	// Scan second blob
	matches2, err := scanner.ScanContent(content2, blobID2, provenance2)
	require.NoError(t, err, "second scan should succeed")
	require.NotEmpty(t, matches2, "should detect matches in second file")

	// Should have 2 matches but only 1 finding (deduplicated by secret value)
	findings, err := scanner.store.GetFindings()
	require.NoError(t, err, "GetFindings should succeed")
	assert.Len(t, findings, 1, "should have exactly 1 deduplicated finding")
}
