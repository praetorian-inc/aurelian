package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const banner = `                      _ _            
  __ _ _   _ _ __ ___| (_) __ _ _ __  
 / _` + "`" + ` | | | | '__/ _ \ | |/ _` + "`" + ` | '_ \ 
| (_| | |_| | | |  __/ | | (_| | | | |
 \__,_|\__,_|_|  \___|_|_|\__,_|_| |_|

 Praetorian Security, Inc.
`

func configureSlog(level string, logger *plugin.Logger) {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default: // "none" — only warn/error pass through
		slogLevel = slog.LevelWarn
	}
	slog.SetDefault(slog.New(plugin.NewSlogHandler(logger, slogLevel)))
}

// platformAliases maps platform names to their command aliases
var platformAliases = map[string][]string{
	"azure": {"az"},
	"aws":   {"amazon"},
	"gcp":   {"google"},
	"m365":  {"microsoft365", "o365"},
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

	// Add flags based on module parameters.
	// Derive []Parameter from the module's config struct (or nil).
	flagValues := make(map[string]interface{})
	paramNames := make(map[string]bool)

	target := module.Parameters()
	if target == nil { // no parameters
		parent.AddCommand(cmd)
		return
	}

	params, err := plugin.ParametersFrom(target)
	if err != nil {
		panic(fmt.Sprintf("module %q has invalid parameter struct: %v", moduleID, err))
	}

	for _, param := range params {
		if paramNames[param.Name] {
			continue
		}
		paramNames[param.Name] = true
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
		_ = cmd.MarkFlagRequired(name)
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

	// Get output flags
	outputDir, _ := cmd.Flags().GetString("output-dir")
	outputFile, _ := cmd.Flags().GetString("output-file")

	// Check if this is the arg-scan module and if enrichment is disabled
	moduleName := module.Name()
	if module.ID() == "arg-scan" {
		if disableEnrichment, _ := cmd.Flags().GetBool("disable-enrichment"); disableEnrichment {
			moduleName = "Azure ARG Template Scanner WITHOUT ENRICHMENT"
		}
	}
	log := plugin.NewLogger(os.Stderr, noColorFlag, quietFlag)
	log.Banner(banner)
	log.Info("running module %s", moduleName)
	configureSlog("none", log)

	// Inject module ID into args for downstream outputters
	argsMap["module-name"] = module.ID()

	// Create config with args, context, and output writer (initially discard, will be set per-format)
	cfg := plugin.Config{
		Args:    argsMap,
		Context: context.Background(),
		Output:  io.Discard,
		Verbose: !quietFlag,
		Log:     log,
	}

	// Run module (parameter binding is handled automatically by ModuleWrapper)
	p1 := pipeline.From[plugin.Config](cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, module.Run, p2)

	results, err := p2.Collect()
	if err != nil {
		return err
	}

	// Output results if there are any
	if len(results) > 0 {
		// Always write the JSON output file first.
		// Determine output file path
		var outputPath string
		if outputFile != "" {
			// User specified explicit file — use as-is
			outputPath = outputFile
		} else {
			// Auto-generate: {output-dir}/{moduleID}-{timestamp}.{ext}
			timestamp := time.Now().Format("20060102-150405")
			filename := fmt.Sprintf("%s-%s%s", module.ID(), timestamp, ".json")
			outputPath = filepath.Join(outputDir, filename)
		}

		// Ensure the output directory exists
		if err := utils.EnsureFileDirectory(outputPath); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()

		formatter := &plugin.JSONFormatter{Writer: f, Pretty: true}
		if err := formatter.Format(results); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		log.Success("output written to %s", outputPath)

		// Additionally seed Neo4j when the user supplied a --neo4j-uri AND the
		// results actually contain graph entities. This makes Neo4j an additive
		// sink alongside the JSON file. We gate on result CONTENT (not the flag
		// alone) so that modules which only READ the graph and emit findings
		// (e.g. `analyze graph` → AurelianRisk) skip seeding — they have no
		// entities to seed, and their JSON findings are already written above.
		if uri, _ := argsMap["neo4j-uri"].(string); uri != "" && resultsContainGraphEntities(results) {
			username, _ := argsMap["neo4j-username"].(string)
			if username == "" {
				username = "neo4j"
			}
			password, _ := argsMap["neo4j-password"].(string)
			if password == "" {
				password = "neo4j"
			}
			graphFormatter, err := plugin.NewGraphFormatter(uri, username, password)
			if err != nil {
				return fmt.Errorf("connecting to Neo4j: %w", err)
			}
			defer func() { _ = graphFormatter.Close() }()
			if err := graphFormatter.Format(results); err != nil {
				return fmt.Errorf("writing results to Neo4j: %w", err)
			}
			log.Success("results also written to Neo4j at %s", uri)
		}
	}

	return nil
}

// resultsContainGraphEntities reports whether the results contain at least one
// graph entity (an AWSIAMResource or AWSIAMRelationship) that GraphFormatter can
// seed into Neo4j. This mirrors GraphFormatter.Format's own collection contract,
// so it cleanly distinguishes "seed the graph" (recon graph) from "read the
// graph + emit findings" (analyze graph → AurelianRisk → no entities).
func resultsContainGraphEntities(results []model.AurelianModel) bool {
	for _, result := range results {
		switch result.(type) {
		case output.AWSIAMResource, output.AWSIAMRelationship:
			return true
		}
	}
	return false
}
