package cmd

import (
	"os"

	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "aws commands",
	Long:  `Execute aws commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var awsAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "aws analyze modules",
	Long:  `Execute aws analyze modules.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var awsReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "AWS recon modules",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	awsCmd.AddCommand(awsAnalyzeCmd)
	awsCmd.AddCommand(awsReconCmd)
	rootCmd.AddCommand(awsCmd)
}

var awsCommonOptions = []*types.Option{
	&options.AwsProfileOpt,
}
