package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/version"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().BoolP("http", "", false, "Use HTTP transport instead of stdio")
	mcpCmd.Flags().StringP("addr", "", ":8080", "HTTP server address")
}

var mcpCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Launch Aurelian's MCP server",
	Long:  `Launch Aurelian's MCP server`,
	Run: func(cmd *cobra.Command, args []string) {

		mcpServer(cmd)
	},
}

func mcpServer(cmd *cobra.Command) {
	s := server.NewMCPServer(
		"Aurelian Server",
		version.FullVersion(),
		server.WithLogging(),
	)

	// Iterate over all registered modules from the new plugin registry
	hierarchy := plugin.GetHierarchy()
	for platform, categories := range hierarchy {
		for category, moduleIDs := range categories {
			for _, moduleID := range moduleIDs {
				mod, ok := plugin.Get(platform, category, moduleID)
				if !ok {
					slog.Warn("Failed to retrieve module", "platform", platform, "category", category, "id", moduleID)
					continue
				}
				tool := pluginToMCPTool(mod)
				s.AddTool(tool, pluginModuleHandler)
			}
		}
	}

	// Get transport flags
	useHTTP, _ := cmd.Flags().GetBool("http")
	addr, _ := cmd.Flags().GetString("addr")

	// Ensure addr is only used with http
	if addr != ":8080" && !useHTTP {
		fmt.Println("Error: --addr flag requires --http to be specified")
		return
	}

	// Start server with selected transport
	if useHTTP {
		sseServer := server.NewSSEServer(s)
		if err := sseServer.Start(addr); err != nil {
			fmt.Printf("HTTP Server error: %v\n", err)
		}
	} else {
		if err := server.ServeStdio(s); err != nil {
			fmt.Printf("Stdio Server error: %v\n", err)
		}
	}
}

func pluginModuleHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse module identifier from tool name (format: platform-category-id)
	// For now, we'll search through the registry to find the module
	// TODO: Optimize this lookup with a reverse index
	hierarchy := plugin.GetHierarchy()
	var targetModule plugin.Module

	for platform, categories := range hierarchy {
		for category, moduleIDs := range categories {
			for _, moduleID := range moduleIDs {
				mod, ok := plugin.Get(platform, category, moduleID)
				if !ok {
					continue
				}
				// Match by ID (tool name should be the module ID)
				if mod.ID() == request.Params.Name {
					targetModule = mod
					break
				}
			}
			if targetModule != nil {
				break
			}
		}
		if targetModule != nil {
			break
		}
	}

	if targetModule == nil {
		return nil, fmt.Errorf("module not found: %s", request.Params.Name)
	}

	// Convert MCP request parameters to plugin Config
	cfg := plugin.Config{
		Args:    make(map[string]any),
		Context: ctx,
		Verbose: false, // TODO: Extract from request if available
	}

	// Extract arguments from MCP request
	if argsMap, ok := request.Params.Arguments.(map[string]any); ok {
		cfg.Args = argsMap
	}

	// Run the module
	results, err := targetModule.Run(cfg)
	if err != nil {
		slog.Error("Module run failed", "module", targetModule.ID(), "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Format results as text
	// TODO: Support structured JSON output
	output := formatResults(results)
	slog.Info("Module completed", "module", targetModule.ID(), "results", len(results))

	return mcp.NewToolResultText(output), nil
}

// formatResults converts plugin.Result slice to text output
func formatResults(results []plugin.Result) string {
	if len(results) == 0 {
		return "No results"
	}

	output := ""
	for i, result := range results {
		if result.Error != nil {
			output += fmt.Sprintf("Result %d: Error: %v\n", i+1, result.Error)
			continue
		}
		output += fmt.Sprintf("Result %d: %v\n", i+1, result.Data)
	}
	return output
}

func pluginToMCPTool(mod plugin.Module) mcp.Tool {
	// Build formatted description with module metadata
	description := fmt.Sprintf("%s\n\nPlatform: %s\nCategory: %s\nOpsec Level: %s\nAuthors: %s\nReferences: %s",
		mod.Description(),
		mod.Platform(),
		mod.Category(),
		mod.OpsecLevel(),
		formatStringSlice(mod.Authors()),
		formatStringSlice(mod.References()),
	)

	openWorldHint := true

	toolOpts := []mcp.ToolOption{
		mcp.WithDescription(description),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:         mod.Name(),
			OpenWorldHint: &openWorldHint,
		}),
	}

	// Add parameters to MCP tool schema
	for _, param := range mod.Parameters() {
		switch param.Type {
		case "string":
			toolOpts = append(toolOpts, mcp.WithString(param.Name,
				mcp.Description(param.Description),
				paramRequiredOption(param.Required),
			))
		case "bool":
			toolOpts = append(toolOpts, mcp.WithBoolean(param.Name,
				mcp.Description(param.Description),
				paramRequiredOption(param.Required),
			))
		case "int":
			toolOpts = append(toolOpts, mcp.WithNumber(param.Name,
				mcp.Description(param.Description),
				paramRequiredOption(param.Required),
			))
		case "[]string":
			toolOpts = append(toolOpts, mcp.WithString(param.Name,
				mcp.Description(param.Description+" (comma-separated values)"),
				paramRequiredOption(param.Required),
			))
		default:
			slog.Warn("Unsupported parameter type", "param", param.Name, "type", param.Type)
			continue
		}
	}

	return mcp.NewTool(mod.ID(), toolOpts...)
}

// formatStringSlice formats a string slice for display
func formatStringSlice(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	output := ""
	for i, item := range items {
		if i > 0 {
			output += ", "
		}
		output += item
	}
	return output
}

// paramRequiredOption returns the appropriate MCP property option for required flag
func paramRequiredOption(required bool) mcp.PropertyOption {
	if required {
		return mcp.Required()
	}
	return func(schema map[string]interface{}) {
		schema["required"] = false
	}
}

