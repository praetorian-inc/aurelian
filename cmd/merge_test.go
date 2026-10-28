package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/escalation"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestModel(t *testing.T, dir, name string, m *escalation.Model) string {
	t.Helper()
	data, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

func testModel(accountID string, roleARN string) *escalation.Model {
	return &escalation.Model{
		Version:  "1.0",
		Accounts: []escalation.Account{{ID: accountID}},
		Principals: []escalation.Principal{
			{ARN: roleARN, Account: accountID, Type: escalation.PrincipalTypeRole},
		},
		PermissionSource: escalation.PermissionSource{
			Type: escalation.PermSourcePolicySummary,
			Entries: []escalation.PolicySummaryEntry{
				{Principal: roleARN, EffectiveStatements: []escalation.PolicyStatement{
					{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
				}},
			},
		},
		Goal: escalation.Goal{Type: escalation.GoalReachAdmin, Attacker: "*"},
	}
}

// newMergeCmd creates a fresh merge command for testing to avoid shared state.
func newMergeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "merge",
		RunE: runMerge,
	}
	cmd.Flags().StringSliceP("input", "i", nil, "Input model.json file paths")
	cmd.Flags().String("input-dir", "", "Directory containing model.json files")
	cmd.Flags().StringP("output", "o", "", "Output file path")
	return cmd
}

func TestMergeCmd_WithInputFiles(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.json")

	pathA := writeTestModel(t, dir, "a.json", testModel("111111111111", "arn:aws:iam::111111111111:role/R1"))
	pathB := writeTestModel(t, dir, "b.json", testModel("222222222222", "arn:aws:iam::222222222222:role/R2"))

	cmd := newMergeCmd()
	cmd.SetArgs([]string{
		"--input", pathA,
		"--input", pathB,
		"--output", outPath,
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var merged escalation.Model
	require.NoError(t, json.Unmarshal(data, &merged))

	assert.Len(t, merged.Accounts, 2)
	assert.Len(t, merged.Principals, 2)
}

func TestMergeCmd_WithInputDir(t *testing.T) {
	dir := t.TempDir()
	modelDir := filepath.Join(dir, "models")
	require.NoError(t, os.Mkdir(modelDir, 0755))
	outPath := filepath.Join(dir, "merged.json")

	writeTestModel(t, modelDir, "a.json", testModel("111111111111", "arn:aws:iam::111111111111:role/R1"))
	writeTestModel(t, modelDir, "b.json", testModel("222222222222", "arn:aws:iam::222222222222:role/R2"))

	cmd := newMergeCmd()
	cmd.SetArgs([]string{
		"--input-dir", modelDir,
		"--output", outPath,
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var merged escalation.Model
	require.NoError(t, json.Unmarshal(data, &merged))

	assert.Len(t, merged.Accounts, 2)
}

func TestMergeCmd_NoInputs_ReturnsError(t *testing.T) {
	cmd := newMergeCmd()
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--input")
}
