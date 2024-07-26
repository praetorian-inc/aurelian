package cmd

import (
	"os"

	"github.com/praetorian-inc/nebula/modules/options"
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

func init() {
	rootCmd.AddCommand(awsCmd)
}

var awsCommonOptions = []*options.Option{
	&options.AwsProfileOpt,
}
