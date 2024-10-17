package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docCmd = &cobra.Command{
	Use:   "gendoc",
	Short: "Generate Markdown documentation",
	Long:  `Generate Markdown documentation for the CLI and its subcommands.`,
	Run: func(cmd *cobra.Command, args []string) {

		excludedCmds := []string{"gendoc", "completion", "job"}
		for _, c := range rootCmd.Commands() {

			for _, e := range excludedCmds {
				if c.Use == e {
					rootCmd.RemoveCommand(c)
					break
				}
			}
		}

		err := doc.GenMarkdownTree(rootCmd, "./docs")
		if err != nil {
			fmt.Println("Error generating documentation:", err)
		} else {
			fmt.Println("Documentation generated in ./docs")
		}
	},
}

func init() {
	rootCmd.AddCommand(docCmd)
}
