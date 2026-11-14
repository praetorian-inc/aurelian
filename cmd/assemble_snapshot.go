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
	Short: "Assemble a solver model from an offline collection snapshot or Terraform plan",
	Long: `Assemble converts a versioned, collector-shaped Aurelian snapshot or
Terraform plan JSON into the model consumed by the escalation solver. It does
not call AWS or require credentials, allowing an authored environment to be
replayed locally.`,
	RunE: runAssembleSnapshot,
}

func init() {
	assembleSnapshotCmd.Flags().String("snapshot", "", "Collection snapshot JSON file")
	assembleSnapshotCmd.Flags().String("terraform-plan", "", "Terraform plan JSON file (terraform show -json)")
	assembleSnapshotCmd.Flags().String("account-id", "", "Account ID for plan-derived resources")
	assembleSnapshotCmd.Flags().String("region", "", "Region for plan-derived resources")
	assembleSnapshotCmd.Flags().String("partition", "aws", "AWS partition for plan-derived resources")
	assembleSnapshotCmd.Flags().String("attacker", "", "Starting principal ARN for plan-derived resources")
	assembleSnapshotCmd.Flags().StringP("output", "o", "", "Output model file (default: stdout)")
}

func runAssembleSnapshot(cmd *cobra.Command, _ []string) error {
	log := plugin.NewLogger(os.Stderr, noColorFlag, quietFlag)
	inputPath, _ := cmd.Flags().GetString("snapshot")
	planPath, _ := cmd.Flags().GetString("terraform-plan")
	outputPath, _ := cmd.Flags().GetString("output")
	if (inputPath == "") == (planPath == "") {
		return fmt.Errorf("provide exactly one of --snapshot or --terraform-plan")
	}

	readPath := inputPath
	if planPath != "" {
		readPath = planPath
	}
	data, err := os.ReadFile(readPath)
	if err != nil {
		return fmt.Errorf("reading offline input %q: %w", readPath, err)
	}
	var snapshot *escalation.CollectionSnapshot
	if planPath == "" {
		snapshot, err = escalation.LoadCollectionSnapshot(data)
	} else {
		accountID, _ := cmd.Flags().GetString("account-id")
		region, _ := cmd.Flags().GetString("region")
		partition, _ := cmd.Flags().GetString("partition")
		attacker, _ := cmd.Flags().GetString("attacker")
		snapshot, err = escalation.CollectionSnapshotFromTerraformPlan(data, escalation.TerraformPlanOptions{
			AccountID: accountID, Region: region, Partition: partition, Attacker: attacker,
		})
	}
	if err != nil {
		return fmt.Errorf("loading offline input: %w", err)
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
