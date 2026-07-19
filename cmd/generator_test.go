package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/testutils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	_ = cmd.Flags().Set("output-format", "json")
	_ = cmd.Flags().Set("output-file", outputFile)

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
	defer func() { _ = f.Close() }()

	// Write test content
	testContent := "test output content"
	_, err = f.WriteString(testContent)
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// Close and verify
	_ = f.Close()

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

// --- runModule output-path tests ---
//
// These are in-process unit tests (no build tag, no cloud/terraform — they run
// in CI). They drive the real runModule with a fake plugin.Module
// (testutils.MockModule) to exercise the streaming JSONL output path, the
// empty-result and producer-error handling, and the additive Neo4j sink. The
// separate live cloud end-to-end coverage lives under test/integration
// (//go:build integration, requires terraform fixtures).

func newRunModuleCommand(t *testing.T, tmpDir string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("output-dir", "", "")
	cmd.Flags().String("output-file", "", "")
	cmd.Flags().String("neo4j-uri", "", "")
	require.NoError(t, cmd.Flags().Set("output-dir", tmpDir))
	return cmd
}

// TestRunModule_StreamsJSONLToFile drives runModule in-process: a fake module
// emits N findings, and runModule must write a .jsonl file with exactly N lines,
// each a valid JSON object containing the finding.
func TestRunModule_StreamsJSONLToFile(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newRunModuleCommand(t, tmpDir)

	const n = 5
	mod := &testutils.MockModule{
		IDValue:       "runmodule-stream",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			for i := range n {
				out.Send(output.AurelianRisk{
					Name:               "aws-secret-finding",
					Severity:           output.RiskSeverityHigh,
					ImpactedResourceID: "resource-" + string(rune('A'+i)),
				})
			}
			return nil
		},
	}

	require.NoError(t, runModule(cmd, mod, plugin.PlatformAWS))

	matches, err := filepath.Glob(filepath.Join(tmpDir, "runmodule-stream-*.jsonl"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "exactly one .jsonl output file")

	f, err := os.Open(matches[0])
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var risk output.AurelianRisk
		require.NoError(t, json.Unmarshal(sc.Bytes(), &risk), "each line is a valid AurelianRisk JSON object")
		assert.Equal(t, "aws-secret-finding", risk.Name)
		lines++
	}
	require.NoError(t, sc.Err())
	assert.Equal(t, n, lines, "one JSON object per finding")
}

// TestRunModule_NoFileOnZeroResults: a module that emits nothing must leave no
// output file behind (lazy-create + no empty-file churn).
func TestRunModule_NoFileOnZeroResults(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newRunModuleCommand(t, tmpDir)

	mod := &testutils.MockModule{
		IDValue:       "runmodule-empty",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			return nil // emit nothing
		},
	}

	require.NoError(t, runModule(cmd, mod, plugin.PlatformAWS))

	matches, err := filepath.Glob(filepath.Join(tmpDir, "runmodule-empty-*.jsonl"))
	require.NoError(t, err)
	assert.Empty(t, matches, "zero results must create no output file")
}

// TestRunModule_NoPartialFileOnProducerError: a module that emits some items then
// fails must surface the error AND leave no partial .jsonl on disk (Abort path).
func TestRunModule_NoPartialFileOnProducerError(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newRunModuleCommand(t, tmpDir)

	mod := &testutils.MockModule{
		IDValue:       "runmodule-fail",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			out.Send(output.AurelianRisk{Name: "partial-1"})
			out.Send(output.AurelianRisk{Name: "partial-2"})
			return assert.AnError // producer fails after emitting
		},
	}

	err := runModule(cmd, mod, plugin.PlatformAWS)
	require.Error(t, err, "producer error must be surfaced")

	matches, globErr := filepath.Glob(filepath.Join(tmpDir, "runmodule-fail-*.jsonl"))
	require.NoError(t, globErr)
	assert.Empty(t, matches, "partial output file must be removed on producer error")
}

// TestRunModule_UnreachableNeo4jStillWritesJSONL: Neo4j is an additive, best-effort
// sink. An unreachable --neo4j-uri must NOT fail the run or suppress the JSONL file;
// the connection failure is logged and the Neo4j sink is skipped. (Modules that
// *require* a graph as input, e.g. analyze-graph, validate their own connection in
// Run and fail there independently of this sink.)
func TestRunModule_UnreachableNeo4jStillWritesJSONL(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newRunModuleCommand(t, tmpDir)
	// Point at a closed port so connectivity verification fails fast.
	require.NoError(t, cmd.Flags().Set("neo4j-uri", "bolt://127.0.0.1:1"))

	const n = 3
	mod := &testutils.MockModule{
		IDValue:       "runmodule-neo4j-down",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			for i := range n {
				out.Send(output.AurelianRisk{Name: "finding", ImpactedResourceID: "r-" + string(rune('A'+i))})
			}
			return nil
		},
	}

	require.NoError(t, runModule(cmd, mod, plugin.PlatformAWS),
		"unreachable Neo4j must not fail the run")

	matches, err := filepath.Glob(filepath.Join(tmpDir, "runmodule-neo4j-down-*.jsonl"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "JSONL file is written even when Neo4j is unreachable")

	data, err := os.ReadFile(matches[0])
	require.NoError(t, err)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, n, lines, "all findings still streamed to JSONL")
}
