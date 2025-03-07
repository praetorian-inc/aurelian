package cmd

import (
	"fmt"
	"runtime"

	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nebula",
	Short: "Nebula - Cloud Security Testing Framework",
	Long: `Nebula is a cloud security testing framework that helps identify
potential security issues in cloud environments.`,
}

func initCommands() {
	runtime.GC()
	rootCmd.AddCommand(listModulesCmd)
	generateCommands(rootCmd)
}

func init() {
}

func Execute() error {
	initCommands()
	return rootCmd.Execute()
}

var listModulesCmd = &cobra.Command{
	Use:   "list-modules",
	Short: "List all available modules",
	Run: func(cmd *cobra.Command, args []string) {
		hierarchy := registry.GetHierarchy()
		for platform, categories := range hierarchy {
			fmt.Printf("\nPlatform: %s\n", platform)
			for category, modules := range categories {
				fmt.Printf("  Category: %s\n", category)
				for _, module := range modules {
					if mod, ok := registry.GetModule(module); ok {
						fmt.Printf("    - %s: %s\n", module, mod.Metadata().Description)
					}
				}
			}
		}
	},
}
