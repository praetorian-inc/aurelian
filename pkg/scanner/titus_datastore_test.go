package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RED: Test that NewPersistentScanner accepts custom dbPath
func TestNewPersistentScanner_CustomPath(t *testing.T) {
	// Ensure clean test environment
	customPath := "test-output/custom-titus.db"
	defer os.RemoveAll("test-output")

	scanner, err := NewPersistentScanner(customPath)
	require.NoError(t, err, "NewPersistentScanner with custom path should succeed")
	require.NotNil(t, scanner, "scanner should not be nil")
	defer scanner.Close()

	// Verify database was created at custom path
	assert.Equal(t, customPath, scanner.DBPath(), "DBPath should return custom path")
	_, err = os.Stat(customPath)
	assert.NoError(t, err, "database file should exist at custom path")
}

// RED: Test that NewPersistentScanner creates parent directories
func TestNewPersistentScanner_CreatesParentDirectories(t *testing.T) {
	// Ensure clean test environment
	customPath := "deeply/nested/path/titus.db"
	defer os.RemoveAll("deeply")

	scanner, err := NewPersistentScanner(customPath)
	require.NoError(t, err, "NewPersistentScanner should create parent directories")
	require.NotNil(t, scanner, "scanner should not be nil")
	defer scanner.Close()

	// Verify parent directories were created
	_, err = os.Stat(filepath.Dir(customPath))
	assert.NoError(t, err, "parent directories should exist")

	// Verify database was created
	_, err = os.Stat(customPath)
	assert.NoError(t, err, "database file should exist")
}

// RED: Test that empty path uses default
func TestNewPersistentScanner_EmptyPathUsesDefault(t *testing.T) {
	// Ensure clean test environment
	defaultPath := "aurelian-output/titus.db"
	defer os.RemoveAll("aurelian-output")

	scanner, err := NewPersistentScanner("")
	require.NoError(t, err, "NewPersistentScanner with empty path should use default")
	require.NotNil(t, scanner, "scanner should not be nil")
	defer scanner.Close()

	// Verify database was created at default path
	assert.Equal(t, defaultPath, scanner.DBPath(), "DBPath should return default path")
	_, err = os.Stat(defaultPath)
	assert.NoError(t, err, "database file should exist at default path")
}

// RED: Test that custom path persists across scanner instances
func TestNewPersistentScanner_CustomPathPersistence(t *testing.T) {
	// Ensure clean test environment
	customPath := "persistent-test/titus.db"
	defer os.RemoveAll("persistent-test")

	content := []byte("test content for persistence")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test.txt"}

	// Create scanner with custom path and scan content
	scanner1, err := NewPersistentScanner(customPath)
	require.NoError(t, err, "NewPersistentScanner should succeed")

	initialMatches, err := scanner1.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent should succeed")

	// Close first scanner
	err = scanner1.Close()
	require.NoError(t, err, "Close should succeed")

	// Verify database file still exists at custom path
	_, err = os.Stat(customPath)
	require.NoError(t, err, "database file should persist after close")

	// Create new scanner with same custom path
	scanner2, err := NewPersistentScanner(customPath)
	require.NoError(t, err, "NewPersistentScanner should succeed with existing db")
	defer scanner2.Close()

	// Scan same content - should find it already exists
	cachedMatches, err := scanner2.ScanContent(content, blobID, provenance)
	require.NoError(t, err, "ScanContent with existing blob should succeed")
	assert.Equal(t, len(initialMatches), len(cachedMatches), "cached matches should have same count")
}
