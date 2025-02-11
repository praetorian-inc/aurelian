package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var listModulesCmd = &cobra.Command{
	Use:   "list-modules",
	Short: "Display available Nebula modules in a tree structure",
	Run: func(cmd *cobra.Command, args []string) {
		displayModuleTree()
	},
}

func displayModuleTree() {
	// Sort modules by command path
	sort.Slice(registeredModules, func(i, j int) bool {
		return registeredModules[i].CommandPath < registeredModules[j].CommandPath
	})

	// Group by top-level command
	cmdGroups := make(map[string][]ModuleInfo)
	for _, module := range registeredModules {
		parts := strings.Split(module.CommandPath, "/")
		if len(parts) > 0 {
			topLevel := parts[0]
			cmdGroups[topLevel] = append(cmdGroups[topLevel], module)
		}
	}

	// Configure colors
	bold := color.New(color.Bold)
	if noColorFlag {
		color.NoColor = true
	}

	// Print each command group and its modules
	cmdNames := make([]string, 0, len(cmdGroups))
	for cmd := range cmdGroups {
		cmdNames = append(cmdNames, cmd)
	}
	sort.Strings(cmdNames)

	for i, cmd := range cmdNames {
		modules := cmdGroups[cmd]

		// Print command header
		fmt.Printf("\n%s\n", bold.Sprint(cmd))

		seenPaths := make(map[string]bool)

		for _, module := range modules {
			parts := strings.Split(module.CommandPath, "/")

			// Print intermediate directories
			for i := 1; i < len(parts)-1; i++ {
				path := strings.Join(parts[1:i+1], "/")
				if !seenPaths[path] {
					indent := strings.Repeat("  ", i-1)
					fmt.Printf("%s├─ %s\n", indent, parts[i])
					seenPaths[path] = true
				}
			}

			// Print module with description
			indent := strings.Repeat("  ", len(parts)-2)
			fmt.Printf("%s├─ %s - %s\n", indent, parts[len(parts)-1], module.Description)
		}

		if i < len(cmdNames)-1 {
			fmt.Println()
		}
	}
	fmt.Println()
}

func init() {
	rootCmd.AddCommand(listModulesCmd)
}
