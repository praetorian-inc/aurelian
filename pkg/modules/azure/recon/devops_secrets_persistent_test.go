package recon

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunUsesPersistentScanner verifies that Run creates and uses PersistentScanner
func TestRunUsesPersistentScanner(t *testing.T) {
	module := &DevOpsSecretsModule{}

	t.Run("creates persistent scanner once", func(t *testing.T) {
		// Create temp directory for test
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "findings.json")

		cfg := plugin.Config{
			Context: context.Background(),
			Output:  io.Discard,
			Args: map[string]interface{}{
				"devops-pat":  "test-pat",
				"devops-org":  "test-org",
				"output-file": outputFile,
				"verbose":     false,
			},
		}

		// Run the module (will fail if scanner not implemented)
		_, err := module.Run(cfg)

		// Should not error on scanner creation
		assert.NoError(t, err, "Expected Run to create PersistentScanner without error")

		// Verify output file was created
		_, err = os.Stat(outputFile)
		assert.NoError(t, err, "Expected output file to exist")
	})
}

// TestScanWithPersistentScanner verifies runNoseyParker uses persistent scanner correctly
func TestScanWithPersistentScanner(t *testing.T) {
	module := &DevOpsSecretsModule{}
	ctx := context.Background()

	t.Run("runNoseyParker works with file", func(t *testing.T) {
		// Create temp directory with test file
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "secret.txt")

		// Write a known secret pattern
		testContent := `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
		err := os.WriteFile(testFile, []byte(testContent), 0644)
		require.NoError(t, err)

		// Create persistent scanner for test
		scanner := createTestScanner(t)
		defer scanner.Close()

		// Run scanner
		findings, err := module.runNoseyParker(ctx, scanner, testFile, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find at least one secret
		assert.NotEmpty(t, findings, "Expected to find at least one secret")
	})
}

// TestPersistentScannerClosed verifies scanner is properly closed
func TestPersistentScannerClosed(t *testing.T) {
	module := &DevOpsSecretsModule{}

	t.Run("scanner closed with defer in Run", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "findings.json")

		cfg := plugin.Config{
			Context: context.Background(),
			Output:  io.Discard,
			Args: map[string]interface{}{
				"devops-pat":  "test-pat",
				"devops-org":  "test-org",
				"output-file": outputFile,
			},
		}

		// Run the module
		_, err := module.Run(cfg)
		assert.NoError(t, err)

		// Verify the SQLite database exists at expected location
		dbPath := "aurelian-output/titus.db"
		_, err = os.Stat(dbPath)
		assert.NoError(t, err, "Expected titus.db to exist after Run completes")
	})
}
