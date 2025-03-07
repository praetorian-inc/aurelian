package cmd

import (
	"os"

	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
)

var miscCmd = &cobra.Command{
	Use:   "misc",
	Short: "misc commands",
	Long:  `Execute misc commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var miscAugmentCmd = &cobra.Command{
	Use:   "augment",
	Short: "misc augment modules",
	Long:  `Execute miscellaneous modules that augment third-party tooling.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	miscCmd.AddCommand(miscAugmentCmd)
	rootCmd.AddCommand(miscCmd)
}

var miscCommonOptions = []*types.Option{
	&options.OutputOpt,
}
