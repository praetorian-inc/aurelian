package cmd

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/spf13/cobra"
)

var (
	logLevelFlag string
	awsCacheLogLevel string
	awsCacheLogFile string
	noColorFlag bool
)

var rootCmd = &cobra.Command{
	Use:   "nebula",
	Short: "Nebula - Cloud Security Testing Framework",
	Long: `Nebula is a cloud security testing framework that helps identify
potential security issues in cloud environments.`,
}

func initCommands() {
	runtime.GC()
	if !strings.Contains(strings.Join(os.Args, " "), "mcp-server") {
		message.Banner(registry.GetModuleCount())
	}
	rootCmd.AddCommand(listModulesCmd)
	generateCommands(rootCmd)
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, options.LogLevel().Name(), options.LogLevel().Value().(string), "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&awsCacheLogLevel, options.AwsCacheLogLevel().Name(), options.AwsCacheLogLevel().Value().(string), "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&awsCacheLogFile, options.AwsCacheLogFile().Name(), options.AwsCacheLogFile().Value().(string), "")
	rootCmd.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
	
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		logs.ConfigureDefaults(logLevelFlag)
		helpers.ConfigureAWSCacheLogger(awsCacheLogLevel, awsCacheLogFile)
		
		// Configure janus-framework logging to match nebula's log level
		if level, err := cfg.LevelFromString(logLevelFlag); err == nil {
			cfg.SetDefaultLevel(level)
		}
	}
}

func Execute() error {
	initCommands()
	return rootCmd.Execute()
}

var listModulesCmd = &cobra.Command{
	Use:   "list-modules",
	Short: "Display available Nebula modules in a tree structure",
	Run: func(cmd *cobra.Command, args []string) {
		displayModuleTree()
	},
}

func displayModuleTree() {
	hierarchy := registry.GetHierarchy()
	
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
				if mod, ok := registry.GetModule(moduleName); ok {
					commandPath := fmt.Sprintf("%s/%s/%s", platform, category, moduleName)
					allModules = append(allModules, ModuleInfo{
						CommandPath: commandPath,
						Description: mod.Metadata().Description,
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
