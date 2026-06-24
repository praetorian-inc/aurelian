package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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

func newE2ECommand(t *testing.T, tmpDir string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("output-dir", "", "")
	cmd.Flags().String("output-file", "", "")
	cmd.Flags().String("neo4j-uri", "", "")
	require.NoError(t, cmd.Flags().Set("output-dir", tmpDir))
	return cmd
}

// TestRunModule_StreamsJSONLToFile drives the real runModule end-to-end: a fake
// module emits N findings, and runModule must write a .jsonl file with exactly N
// lines, each a valid JSON object containing the finding.
func TestRunModule_StreamsJSONLToFile(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newE2ECommand(t, tmpDir)

	const n = 5
	mod := &testutils.MockModule{
		IDValue:       "e2e-stream",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			for i := 0; i < n; i++ {
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

	matches, err := filepath.Glob(filepath.Join(tmpDir, "e2e-stream-*.jsonl"))
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
	cmd := newE2ECommand(t, tmpDir)

	mod := &testutils.MockModule{
		IDValue:       "e2e-empty",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
		RunFn: func(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
			return nil // emit nothing
		},
	}

	require.NoError(t, runModule(cmd, mod, plugin.PlatformAWS))

	matches, err := filepath.Glob(filepath.Join(tmpDir, "e2e-empty-*.jsonl"))
	require.NoError(t, err)
	assert.Empty(t, matches, "zero results must create no output file")
}

// TestRunModule_NoPartialFileOnProducerError: a module that emits some items then
// fails must surface the error AND leave no partial .jsonl on disk (Abort path).
func TestRunModule_NoPartialFileOnProducerError(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newE2ECommand(t, tmpDir)

	mod := &testutils.MockModule{
		IDValue:       "e2e-fail",
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

	matches, globErr := filepath.Glob(filepath.Join(tmpDir, "e2e-fail-*.jsonl"))
	require.NoError(t, globErr)
	assert.Empty(t, matches, "partial output file must be removed on producer error")
}
