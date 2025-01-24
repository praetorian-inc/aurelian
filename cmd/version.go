package cmd

import (
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Nebula",
	Long:  `All software has versions. This is Nebula's`,
	Run: func(cmd *cobra.Command, args []string) {
		message.Info(version.FullVersion())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
