package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/escalation"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/spf13/cobra"
)

var assembleSnapshotCmd = &cobra.Command{
	Use:   "assemble",
	Short: "Assemble a solver model from an offline collection snapshot",
	Long: `Assemble converts a versioned, collector-shaped Aurelian snapshot into
the model consumed by the escalation solver. It does not call AWS or require
credentials, allowing an authored environment to be replayed locally.`,
	RunE: runAssembleSnapshot,
}

func init() {
	assembleSnapshotCmd.Flags().String("snapshot", "", "Collection snapshot JSON file")
	assembleSnapshotCmd.Flags().StringP("output", "o", "", "Output model file (default: stdout)")
	if err := assembleSnapshotCmd.MarkFlagRequired("snapshot"); err != nil {
		panic(err)
	}
}

func runAssembleSnapshot(cmd *cobra.Command, _ []string) error {
	log := plugin.NewLogger(os.Stderr, noColorFlag, quietFlag)
	inputPath, _ := cmd.Flags().GetString("snapshot")
	outputPath, _ := cmd.Flags().GetString("output")

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading collection snapshot %q: %w", inputPath, err)
	}
	snapshot, err := escalation.LoadCollectionSnapshot(data)
	if err != nil {
		return err
	}
	model, err := snapshot.Assemble()
	if err != nil {
		return fmt.Errorf("assembling collection snapshot: %w", err)
	}
	modelData, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing model: %w", err)
	}

	if outputPath == "" {
		if _, err := os.Stdout.Write(modelData); err != nil {
			return fmt.Errorf("writing model: %w", err)
		}
		fmt.Fprintln(os.Stdout)
		return nil
	}
	if err := os.WriteFile(outputPath, modelData, 0600); err != nil {
		return fmt.Errorf("writing model %q: %w", outputPath, err)
	}
	if err := os.Chmod(outputPath, 0600); err != nil {
		return fmt.Errorf("setting model permissions %q: %w", outputPath, err)
	}
	log.Success("model assembled (principals: %d, resources: %d, structural_facts: %d)",
		len(model.Principals), len(model.Resources), len(model.StructuralFacts))
	return nil
}
