package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/escalation"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/spf13/cobra"
)

var escalationCmd = &cobra.Command{
	Use:   "escalation",
	Short: "Escalation model utilities",
}

var mergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merge per-account escalation models into an org-wide model",
	Long: `Merge multiple per-account escalation-solver model.json files into a
single org-wide model for cross-account privilege escalation analysis.

Account-root trust relationships (arn:aws:iam::ACCOUNT:root) are preserved
in the merged model for solver-side interpretation.`,
	RunE: runMerge,
}

func init() {
	mergeCmd.Flags().StringSliceP("input", "i", nil, "Input model.json file paths (repeatable)")
	mergeCmd.Flags().String("input-dir", "", "Directory containing model.json files (alternative to --input)")
	mergeCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
}

func runMerge(cmd *cobra.Command, args []string) error {
	log := plugin.NewLogger(os.Stderr, noColorFlag, quietFlag)

	inputFiles, _ := cmd.Flags().GetStringSlice("input")
	inputDir, _ := cmd.Flags().GetString("input-dir")
	outputPath, _ := cmd.Flags().GetString("output")

	if len(inputFiles) == 0 && inputDir == "" {
		return fmt.Errorf("provide --input files or --input-dir")
	}

	if inputDir != "" {
		var exclude []string
		if outputPath != "" {
			exclude = append(exclude, outputPath)
		}
		globbed, err := escalation.GlobModelFiles(inputDir, exclude...)
		if err != nil {
			return err
		}
		if len(globbed) == 0 {
			return fmt.Errorf("no .json files found in %s", inputDir)
		}
		inputFiles = append(inputFiles, globbed...)
	}

	if outputPath != "" {
		absOut, err := filepath.Abs(outputPath)
		if err != nil {
			return fmt.Errorf("resolving output path: %w", err)
		}
		for _, in := range inputFiles {
			absIn, err := filepath.Abs(in)
			if err != nil {
				return fmt.Errorf("resolving input path %q: %w", in, err)
			}
			if absIn == absOut {
				return fmt.Errorf("output path %q is also an input file; refusing to overwrite source", outputPath)
			}
		}
	}

	inputFiles = escalation.DeduplicatePaths(inputFiles)
	log.Info("merging %d model file(s)", len(inputFiles))

	merged, err := escalation.LoadAndMergeModelFiles(inputFiles)
	if err != nil {
		return fmt.Errorf("merge failed: %w", err)
	}

	stats := escalation.MergeStats(merged)
	log.Success("merged: %d accounts, %d principals, %d resources, %d structural facts",
		stats.Accounts, stats.Principals, stats.Resources, stats.StructuralFacts)

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing merged model: %w", err)
	}

	if outputPath == "" {
		_, err = os.Stdout.Write(data)
		if err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
		fmt.Fprintln(os.Stdout)
		return nil
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("writing to %s: %w", outputPath, err)
	}
	if err := os.Chmod(outputPath, 0600); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", outputPath, err)
	}
	log.Success("output written to %s", outputPath)
	return nil
}
