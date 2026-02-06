package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// platformAliases maps platform names to their command aliases
var platformAliases = map[string][]string{
	"azure": {"az"},
	"aws":   {"amazon"},
	"gcp":   {"google"},
	// Add more platform aliases as needed
}

// generateCommands builds the command tree based on registered modules
func generateCommands(root *cobra.Command) {
	hierarchy := plugin.GetHierarchy()

	// Create the full platform->category->module hierarchy
	for platform, categories := range hierarchy {
		platformCmd := &cobra.Command{
			Use:     string(platform),
			Aliases: platformAliases[string(platform)], // Add aliases if they exist
			Short:   fmt.Sprintf("%s platform commands", platform),
		}

		for category, modules := range categories {
			categoryCmd := &cobra.Command{
				Use:   string(category),
				Short: fmt.Sprintf("%s commands for %s", category, platform),
			}

			for _, moduleID := range modules {
				generateModuleCommand(platform, category, moduleID, categoryCmd)
			}

			platformCmd.AddCommand(categoryCmd)
		}

		root.AddCommand(platformCmd)
	}
}

func generateModuleCommand(platform plugin.Platform, category plugin.Category, moduleID string, parent *cobra.Command) {
	module, ok := plugin.Get(platform, category, moduleID)
	if !ok {
		return
	}

	cmd := &cobra.Command{
		Use:   moduleID,
		Short: module.Description(),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runModule(cmd, module, platform)
		},
	}

	// Add flags based on module parameters
	flagValues := make(map[string]interface{})

	// Create a set of parameter names to track which ones we've seen
	paramNames := make(map[string]bool)

	for _, param := range module.Parameters() {
		// Skip if we've already added this parameter
		if paramNames[param.Name] {
			continue
		}

		// Mark as seen
		paramNames[param.Name] = true

		// Add the flag
		addFlag(cmd, param, flagValues)
	}

	parent.AddCommand(cmd)
}

// isShorthandAvailable checks if a shorthand flag is already in use
func isShorthandAvailable(flags *pflag.FlagSet, shorthand string) bool {
	if shorthand == "" {
		return false
	}
	found := false
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Shorthand == shorthand {
			found = true
		}
	})
	return !found
}

func addFlag(cmd *cobra.Command, param plugin.Parameter, flagValues map[string]interface{}) {
	name := param.Name
	shorthand := ""
	// Only use first character of shortcode as shorthand if available
	if len(param.Shortcode) > 0 {
		potentialShorthand := string(param.Shortcode[0])
		if isShorthandAvailable(cmd.Flags(), potentialShorthand) {
			shorthand = potentialShorthand
		}
	}
	description := param.Description

	// Add (required) to description if param is required
	if param.Required {
		description = description + " (required)"
	}

	hasDefault := param.Default != nil

	switch param.Type {
	case "string":
		if hasDefault {
			defaultVal, _ := param.Default.(string)
			if shorthand != "" {
				flagValues[name] = cmd.Flags().StringP(name, shorthand, defaultVal, description)
			} else {
				flagValues[name] = cmd.Flags().String(name, defaultVal, description)
			}
		} else {
			if shorthand != "" {
				flagValues[name] = cmd.Flags().StringP(name, shorthand, "", description)
			} else {
				flagValues[name] = cmd.Flags().String(name, "", description)
			}
		}
	case "int":
		if hasDefault {
			defaultVal, _ := param.Default.(int)
			if shorthand != "" {
				flagValues[name] = cmd.Flags().IntP(name, shorthand, defaultVal, description)
			} else {
				flagValues[name] = cmd.Flags().Int(name, defaultVal, description)
			}
		} else {
			if shorthand != "" {
				flagValues[name] = cmd.Flags().IntP(name, shorthand, 0, description)
			} else {
				flagValues[name] = cmd.Flags().Int(name, 0, description)
			}
		}
	case "bool":
		if hasDefault {
			defaultVal, _ := param.Default.(bool)
			if shorthand != "" {
				flagValues[name] = cmd.Flags().BoolP(name, shorthand, defaultVal, description)
			} else {
				flagValues[name] = cmd.Flags().Bool(name, defaultVal, description)
			}
		} else {
			if shorthand != "" {
				flagValues[name] = cmd.Flags().BoolP(name, shorthand, false, description)
			} else {
				flagValues[name] = cmd.Flags().Bool(name, false, description)
			}
		}
	case "[]string":
		if hasDefault {
			defaultVal, _ := param.Default.([]string)
			if shorthand != "" {
				flagValues[name] = cmd.Flags().StringSliceP(name, shorthand, defaultVal, description)
			} else {
				flagValues[name] = cmd.Flags().StringSlice(name, defaultVal, description)
			}
		} else {
			if shorthand != "" {
				flagValues[name] = cmd.Flags().StringSliceP(name, shorthand, []string{}, description)
			} else {
				flagValues[name] = cmd.Flags().StringSlice(name, []string{}, description)
			}
		}
	}

	if param.Required {
		cmd.MarkFlagRequired(name)
	}
}

// Update runModule to accept platform string
func runModule(cmd *cobra.Command, module plugin.Module, platform plugin.Platform) error {
	// Convert flags to args map
	argsMap := make(map[string]any)
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			name := flag.Name

			// Handle different flag types
			switch flag.Value.Type() {
			case "bool":
				value, _ := cmd.Flags().GetBool(name)
				argsMap[name] = value
			case "int":
				value, _ := cmd.Flags().GetInt(name)
				argsMap[name] = value
			case "stringSlice":
				value, _ := cmd.Flags().GetStringSlice(name)
				argsMap[name] = value
			case "string":
				value, _ := cmd.Flags().GetString(name)
				argsMap[name] = value
			default:
				// Fallback to string representation
				argsMap[name] = flag.Value.String()
			}
		}
	})

	// Get output format and output path from flags
	outputFormat, _ := cmd.Flags().GetString("output-format")
	outputPath, _ := cmd.Flags().GetString("output-file")

	// Determine output writer and file cleanup
	var outputWriter io.Writer = os.Stdout
	var outputFile *os.File
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		outputFile = f
		outputWriter = f
		defer func() {
			if closeErr := outputFile.Close(); closeErr != nil {
				// Log close error but don't override return value
				message.Warning("failed to close output file: %v", closeErr)
			}
		}()
	}

	// Check if this is the arg-scan module and if enrichment is disabled
	moduleName := module.Name()
	if module.ID() == "arg-scan" {
		if disableEnrichment, _ := cmd.Flags().GetBool("disable-enrichment"); disableEnrichment {
			moduleName = "Azure ARG Template Scanner WITHOUT ENRICHMENT"
		}
	}
	message.Section("Running module %s", moduleName)

	// Create config with args, context, and output writer
	cfg := plugin.Config{
		Args:    argsMap,
		Context: context.Background(),
		Output:  outputWriter,
		Verbose: !quietFlag, // Verbose is inverse of quiet
	}

	// Run module with the new plugin API
	results, err := module.Run(cfg)
	if err != nil {
		return err
	}

	// Output results if there are any
	if len(results) > 0 {
		var formatter plugin.Formatter

		switch outputFormat {
		case "json":
			// Clean JSON output
			formatter = &plugin.JSONFormatter{
				Writer: outputWriter,
				Pretty: false,
			}
		default:
			// Default/pretty format: summary message + pretty JSON
			if outputFormat == "" || outputFormat == "default" {
				// Show summary message for default format
				message.Section("Module results:")
			}
			formatter = &plugin.JSONFormatter{
				Writer: outputWriter,
				Pretty: true,
			}
		}

		// Format and output results
		if err := formatter.Format(results); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
	}

	if platform == plugin.PlatformAWS && !quietFlag {
		helpers.ShowCacheStat()
		helpers.PrintAllThrottlingCounts()
	}

	return nil
}
