package cmd

import (
	"fmt"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// generateCommands builds the command tree based on registered modules
func generateCommands(root *cobra.Command) {
	hierarchy := registry.GetHierarchy()

	// Create the full platform->category->module hierarchy
	for platform, categories := range hierarchy {
		platformCmd := &cobra.Command{
			Use:   platform,
			Short: fmt.Sprintf("%s platform commands", platform),
		}

		for category, modules := range categories {
			categoryCmd := &cobra.Command{
				Use:   category,
				Short: fmt.Sprintf("%s commands for %s", category, platform),
			}

			for _, module := range modules {
				generateModuleCommand(module, categoryCmd)
			}

			platformCmd.AddCommand(categoryCmd)
		}

		root.AddCommand(platformCmd)
	}
}

func generateModuleCommand(moduleName string, parent *cobra.Command) {
	entry, ok := registry.GetRegistryEntry(moduleName)
	if !ok {
		return
	}

	cmd := &cobra.Command{
		Use:   moduleName,
		Short: entry.Module.Metadata().Description,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runModule(cmd, entry.Module)
		},
	}

	// Add flags based on module parameters
	flagValues := make(map[string]interface{})

	// Here's the issue - you might be collecting duplicate parameters
	// Let's ensure we only add each parameter once:

	// Create a set of parameter names to track which ones we've seen
	paramNames := make(map[string]bool)

	for _, param := range entry.Module.Params() {
		// Skip if we've already added this parameter
		if paramNames[param.Name()] {
			continue
		}

		// Mark as seen
		paramNames[param.Name()] = true

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

func addFlag(cmd *cobra.Command, param cfg.Param, flagValues map[string]interface{}) {
	name := param.Name()
	shorthand := ""
	// Only use first character of shortcode as shorthand if available
	if sc := param.Shortcode(); len(sc) > 0 {
		potentialShorthand := string(sc[0])
		if isShorthandAvailable(cmd.Flags(), potentialShorthand) {
			shorthand = potentialShorthand
		}
	}
	description := param.Description()

	// Add (required) to description if param is required
	if param.Required() {
		description = description + " (required)"
	}

	switch param.Type() {
	case "string":
		if param.HasDefault() {
			defaultVal, _ := cfg.As[string](param.Value())
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
		if param.HasDefault() {
			defaultVal, _ := cfg.As[int](param.Value())
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
		if param.HasDefault() {
			defaultVal, _ := cfg.As[bool](param.Value())
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
		if param.HasDefault() {
			defaultVal, _ := cfg.As[[]string](param.Value())
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

	if param.Required() {
		cmd.MarkFlagRequired(name)
	}
}

func runModule(cmd *cobra.Command, module chain.Module) error {
	// Convert flags to configs
	var configs []cfg.Config
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			name := flag.Name

			// Handle different flag types
			switch flag.Value.Type() {
			case "bool":
				value, _ := cmd.Flags().GetBool(name)
				configs = append(configs, cfg.WithArg(name, value))
			case "int":
				value, _ := cmd.Flags().GetInt(name)
				configs = append(configs, cfg.WithArg(name, value))
			case "stringSlice":
				value, _ := cmd.Flags().GetStringSlice(name)
				configs = append(configs, cfg.WithArg(name, value))
			case "string":
				value, _ := cmd.Flags().GetString(name)
				configs = append(configs, cfg.WithArg(name, value))
			default:
				// Fallback to string representation
				configs = append(configs, cfg.WithArg(name, flag.Value.String()))
			}
		}
	})

	message.Section("Running module %s", module.Metadata().Name)
	module.Run(configs...)
	helpers.ShowCacheStat()
	helpers.PrintAllThrottlingCounts()
	return module.Error()
}

func getFirstKey(m interface{}) string {
	switch v := m.(type) {
	case map[string]map[string][]string:
		for k := range v {
			return k
		}
	case map[string][]string:
		for k := range v {
			return k
		}
	}
	return ""
}
