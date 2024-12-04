package cmd

import (
	"os"

	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
)

var azureCmd = &cobra.Command{
	Use:     "azure",
	Aliases: []string{"az"},
	Short:   "azure commands",
	Long:    `Execute azure commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var azureReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Azure recon modules",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	azureCmd.AddCommand(azureReconCmd)
	rootCmd.AddCommand(azureCmd)
}

var azureCommonOptions = []*types.Option{}
