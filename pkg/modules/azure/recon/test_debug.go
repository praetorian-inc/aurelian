package recon

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	
	"github.com/praetorian-inc/aurelian/pkg/scanner"
	"github.com/stretchr/testify/require"
)

func TestDebugScanner(t *testing.T) {
	module := &DevOpsSecretsModule{}
	ctx := context.Background()
	
	// Create temp directory with test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "config.txt")

	// Write a known secret pattern (AWS access key format)
	testContent := `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	// Create persistent scanner for test
	tmpDir2 := t.TempDir()
	origDir := os.Getenv("AURELIAN_OUTPUT_DIR")
	os.Setenv("AURELIAN_OUTPUT_DIR", tmpDir2)
	defer func() {
		if origDir == "" {
			os.Unsetenv("AURELIAN_OUTPUT_DIR")
		} else {
			os.Setenv("AURELIAN_OUTPUT_DIR", origDir)
		}
	}()

	scanner, err := scanner.NewPersistentScanner("")
	require.NoError(t, err)
	defer scanner.Close()

	// Run scanner
	findings, err := module.runNoseyParker(ctx, scanner, testFile, false, io.Discard)

	// Debug output
	fmt.Printf("Error: %v\n", err)
	fmt.Printf("Findings count: %d\n", len(findings))
	for i, f := range findings {
		fmt.Printf("Finding %d: %+v\n", i, f)
	}
}
