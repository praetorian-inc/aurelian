package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/modules/aws/recon"
	"github.com/praetorian-inc/nebula/version"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.Flags().BoolP("http", "", false, "Use HTTP transport instead of stdio")
	mcpCmd.Flags().StringP("addr", "", ":8080", "HTTP server address")
}

var mcpCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Launch Nebula's MCP server",
	Long:  `Launch Nebula's MCP server`,
	Run: func(cmd *cobra.Command, args []string) {

		mcpServer(cmd)
	},
}

func mcpServer(cmd *cobra.Command) {
	s := server.NewMCPServer(
		"Nebula Server",
		version.FullVersion(),
		server.WithLogging(),
	)

	// TODO: Tools need to be prefixed with "nebula-platform-"
	for _, categories := range registry.GetHierarchy() {
		for _, modules := range categories {
			for _, moduleName := range modules {
				module, _ := registry.GetRegistryEntry(moduleName)
				tool := chainToToolAdpater(&module.Module)
				s.AddTool(tool, moduleHandler)
			}
		}
	}

	tool := chainToToolAdpater(recon.AWSPublicResources)

	// Add tool handler
	s.AddTool(tool, moduleHandler)

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

func moduleHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var configs []cfg.Config
	w := &bytes.Buffer{}
	configs = append(configs, cfg.WithArg("writer", w))

	entry, ok := registry.GetRegistryEntry(request.Params.Name)
	if !ok {
		return nil, fmt.Errorf("module not found")
	}

	mod := entry.Module
	mod.WithOutputters(output.NewWriterOutputter)
	configs = append(configs, mcpParamToJanusParam(request, mod.New().Params())...)

	err := mod.Run(configs...)
	if err != nil {
		slog.Error("Module run failed", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	slog.Info("Module ran", "output", w.String())

	if mod.Error() != nil {
		slog.Error("Module run failed", "error", mod.Error())
		return mcp.NewToolResultError(mod.Error().Error()), nil
	}

	return mcp.NewToolResultText(w.String()), nil
}

func chainToToolAdpater(mod *chain.Module) mcp.Tool {
	metadata := (*mod).Metadata()
	if metadata == nil {
		metadata = &cfg.Metadata{
			Name:        "unknown",
			Description: "No description available",
		}
	}

	props := metadata.Properties()
	description := fmt.Sprintf("%s\n\nPlatform: %s\nOpsec Level: %s\nAuthors: %s\nReferences: %s\nName: %s",
		metadata.Description,
		getProp(props, "platform"),
		getProp(props, "opsec_level"),
		getProp(props, "authors"),
		getProp(props, "references"),
		metadata.Name,
	)

	openWorldHint := true

	toolOpts := []mcp.ToolOption{
		mcp.WithDescription(description),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:         metadata.Name,
			OpenWorldHint: &openWorldHint,
		}),
	}

	instance := (*mod).New()
	if instance != nil {
		for _, param := range instance.Params() {
			switch param.Value().(type) {
			case string:
				toolOpts = append(toolOpts, mcp.WithString(param.Name(),
					mcp.Description(param.Description()),
					janusReqToMcpReq(param),
				))
			case bool:
				toolOpts = append(toolOpts, mcp.WithBoolean(param.Name(),
					mcp.Description(param.Description()),
					janusReqToMcpReq(param),
				))
			case int:
				toolOpts = append(toolOpts, mcp.WithNumber(param.Name(),
					mcp.Description(param.Description()),
					janusReqToMcpReq(param),
				))
			case []string:
				toolOpts = append(toolOpts, mcp.WithString(param.Name(),
					mcp.Description(param.Description()+" that supports comma separated values"),
					janusReqToMcpReq(param),
				))
			default:
				slog.Warn("Unsupported parameter type", "param", param.Name())
				continue
			}
		}
	}

	return mcp.NewTool(metadata.Properties()["id"].(string), toolOpts...)
}

func janusReqToMcpReq(param cfg.Param) mcp.PropertyOption {
	if param.Required() {
		return mcp.Required()
	}

	return func(schema map[string]interface{}) {
		schema["required"] = false
	}
}

func mcpParamToJanusParam(request mcp.CallToolRequest, jparams []cfg.Param) []cfg.Config {
	var configs []cfg.Config

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return configs
	}

	for _, param := range jparams {
		p := argsMap[param.Name()]
		if p == nil {
			continue
		}
		configs = append(configs, cfg.WithArg(param.Name(), p))
	}

	return configs
}

func getProp(props map[string]interface{}, key string) string {
	if v, ok := props[key]; ok && v != nil {
		switch val := v.(type) {
		case string:
			return val
		case []string:
			if len(val) == 0 {
				return "none"
			}
			items := make([]string, len(val))
			for i, item := range val {
				items[i] = fmt.Sprintf("- %s", item)
			}
			return "\n" + strings.Join(items, "\n")
		}
	}
	return "unknown"
}
