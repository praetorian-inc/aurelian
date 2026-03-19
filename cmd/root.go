package cmd

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/spf13/cobra"
)

var (
	noColorFlag bool
	quietFlag   bool
)

var rootCmd = &cobra.Command{
	Use:   "aurelian",
	Short: "Aurelian - Cloud Security Testing Framework",
	Long: `Aurelian is a cloud security testing framework that helps identify
potential security issues in cloud environments.`,
}

func initCommands() {
	runtime.GC()
	rootCmd.AddCommand(listModulesCmd)
	generateCommands(rootCmd)
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "Suppress user messages (overrides default verbose CLI mode)")
	rootCmd.PersistentFlags().String("output-dir", "aurelian-output", "Output directory (default: aurelian-output)")
	rootCmd.PersistentFlags().StringP("output-file", "f", "", "Output file path (overrides --output-dir)")
}

func Execute() error {
	initCommands()
	return rootCmd.Execute()
}

var listModulesCmd = &cobra.Command{
	Use:   "list-modules",
	Short: "Display available Aurelian modules in a tree structure",
	Run: func(cmd *cobra.Command, args []string) {
		log := plugin.NewLogger(os.Stderr, noColorFlag, quietFlag)
		log.Banner(banner + moduleCounts())
		displayModuleTree()
	},
}

func moduleCounts() string {
	hierarchy := plugin.GetHierarchy()
	counts := make(map[plugin.Platform]int)
	for platform, categories := range hierarchy {
		for _, modules := range categories {
			counts[platform] += len(modules)
		}
	}
	return fmt.Sprintf(" %d AWS, %d Azure, %d GCP modules",
		counts[plugin.PlatformAWS],
		counts[plugin.PlatformAzure],
		counts[plugin.PlatformGCP],
	)
}

func displayModuleTree() {
	hierarchy := plugin.GetHierarchy()

	// Create module info structs for the tree display
	type ModuleInfo struct {
		CommandPath string
		Description string
	}

	var allModules []ModuleInfo

	// Convert registry hierarchy to command paths
	for platform, categories := range hierarchy {
		for category, moduleNames := range categories {
			for _, moduleName := range moduleNames {
				if mod, ok := plugin.Get(platform, category, moduleName); ok {
					commandPath := fmt.Sprintf("%s/%s/%s", platform, category, moduleName)
					allModules = append(allModules, ModuleInfo{
						CommandPath: commandPath,
						Description: mod.Description(),
					})
				}
			}
		}
	}

	// Sort modules by command path
	sort.Slice(allModules, func(i, j int) bool {
		return allModules[i].CommandPath < allModules[j].CommandPath
	})

	// Group by top-level command (platform)
	cmdGroups := make(map[string][]ModuleInfo)
	for _, module := range allModules {
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

		// Print platform header
		fmt.Printf("\n%s\n", bold.Sprint(cmd))

		seenPaths := make(map[string]bool)

		for _, module := range modules {
			parts := strings.Split(module.CommandPath, "/")

			// Print intermediate directories (categories)
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
