package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var saasCmd = &cobra.Command{
	Use:   "saas",
	Short: "saas commands",
	Long:  `Execute SaaS commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var saasReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "SaaS recon modules",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	saasCmd.AddCommand(saasReconCmd)
	rootCmd.AddCommand(saasCmd)
}
