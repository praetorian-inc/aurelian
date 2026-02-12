package cmd

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Aurelian",
	Long:  `All software has versions. This is Aurelian's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version.FullVersion())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
