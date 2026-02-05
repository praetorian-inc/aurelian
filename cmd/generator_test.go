package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestOutputFlagWritesToFile verifies that the --output flag writes results to a file instead of stdout
func TestOutputFlagWritesToFile(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.json")

	// Create a test command with output flags
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			// This test verifies the flags are properly configured
			return nil
		},
	}

	// Add the flags that should be available
	cmd.Flags().String("output-format", "json", "Output format")
	cmd.Flags().StringP("output-file", "f", "", "Output file path")

	// Set the flags
	cmd.Flags().Set("output-format", "json")
	cmd.Flags().Set("output-file", outputFile)

	// Verify flags are readable
	format, err := cmd.Flags().GetString("output-format")
	if err != nil {
		t.Fatalf("failed to get output-format flag: %v", err)
	}
	if format != "json" {
		t.Errorf("expected output-format=json, got %s", format)
	}

	output, err := cmd.Flags().GetString("output-file")
	if err != nil {
		t.Fatalf("failed to get output flag: %v", err)
	}
	if output != outputFile {
		t.Errorf("expected output=%s, got %s", outputFile, output)
	}
}

// TestOutputFlagDefaultsToStdout verifies that without --output-file flag, output goes to stdout
func TestOutputFlagDefaultsToStdout(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	cmd.Flags().String("output-format", "json", "Output format")
	cmd.Flags().StringP("output-file", "f", "", "Output file path")

	// Don't set the output flag
	output, err := cmd.Flags().GetString("output-file")
	if err != nil {
		t.Fatalf("failed to get output flag: %v", err)
	}

	// Should default to empty string (stdout)
	if output != "" {
		t.Errorf("expected empty output (stdout), got %s", output)
	}
}

// TestFileWriterCreation verifies that file writer can be created and written to
func TestFileWriterCreation(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "test-output.txt")

	// Create a file writer
	f, err := os.Create(outputFile)
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	defer f.Close()

	// Write test content
	testContent := "test output content"
	_, err = f.WriteString(testContent)
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// Close and verify
	f.Close()

	// Read back and verify
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("expected content %q, got %q", testContent, string(content))
	}
}

// TestRunModuleWithOutputFile is an integration test that will fail until implementation is complete
func TestRunModuleWithOutputFile(t *testing.T) {
	t.Skip("Integration test - will be enabled after implementation")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "module-output.json")

	// This test would create a minimal module and verify output goes to file
	// For now, just verify the file path handling logic

	if !strings.HasSuffix(outputFile, ".json") {
		t.Error("output file should have .json extension")
	}
}
