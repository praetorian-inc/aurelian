package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

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
