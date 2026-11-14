package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/escalation"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRunAssembleSnapshotBuildsModelFromCollectorReplay(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "collection-snapshot.json")
	output := filepath.Join(dir, "model.json")
	snapshot := escalation.CollectionSnapshot{
		Version: escalation.CollectionSnapshotVersion,
		GAAD: types.NewAuthorizationAccountDetails(
			"111111111111",
			[]types.UserDetail{{Arn: "arn:aws:iam::111111111111:user/developer", UserName: "developer"}},
			nil, nil, nil,
		),
	}
	data, err := json.Marshal(snapshot)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(input, data, 0600))

	command := &cobra.Command{}
	command.Flags().String("snapshot", input, "")
	command.Flags().String("output", output, "")
	require.NoError(t, runAssembleSnapshot(command, nil))

	modelData, err := os.ReadFile(output)
	require.NoError(t, err)
	var model escalation.Model
	require.NoError(t, json.Unmarshal(modelData, &model))
	require.Len(t, model.Principals, 1)
	info, err := os.Stat(output)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
