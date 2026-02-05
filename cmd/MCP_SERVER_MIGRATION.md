# MCP Server Migration to Plugin Registry

## Summary

Fixed the MCP server (`cmd/mcp-server.go`) to use the new plugin registry architecture instead of the deprecated Janus framework registry.

## Changes Made

### 1. Updated Imports

**Removed:**
- `github.com/praetorian-inc/janus-framework/pkg/chain`
- `github.com/praetorian-inc/janus-framework/pkg/chain/cfg`
- `github.com/praetorian-inc/janus-framework/pkg/output`
- `github.com/praetorian-inc/diocletian/internal/registry`
- `github.com/praetorian-inc/diocletian/pkg/modules/aws/recon`
- `bytes` and `strings` (no longer needed)

**Added:**
- `github.com/praetorian-inc/diocletian/pkg/plugin`

### 2. Replaced Registry API Calls

**Old (Broken):**
```go
for _, categories := range registry.GetHierarchy() {
    for _, modules := range categories {
        for _, moduleName := range modules {
            module, _ := registry.GetRegistryEntry(moduleName)
            tool := chainToToolAdpater(&module.Module)
            s.AddTool(tool, moduleHandler)
        }
    }
}

tool := chainToToolAdpater(recon.AWSPublicResources) // ← BROKEN: variable doesn't exist
s.AddTool(tool, moduleHandler)
```

**New (Working):**
```go
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
```

### 3. Created New Adapter Function

Replaced `chainToToolAdapter(*chain.Module)` with `pluginToMCPTool(plugin.Module)`:

- Converts `plugin.Module` interface to `mcp.Tool`
- Extracts metadata: Platform, Category, OpsecLevel, Authors, References
- Maps plugin parameters to MCP tool schema
- Supports parameter types: string, bool, int, []string

### 4. Created New Handler Function

Replaced `moduleHandler()` with `pluginModuleHandler()`:

- Searches registry by module ID to find target module
- Converts MCP request to `plugin.Config`
- Calls `module.Run(cfg)` with new plugin interface
- Formats `[]plugin.Result` as text output
- Includes TODOs for optimization (reverse index lookup) and structured JSON output

### 5. Added Helper Functions

- `formatResults([]plugin.Result) string`: Converts plugin results to text
- `formatStringSlice([]string) string`: Formats string slices for display
- `paramRequiredOption(bool) mcp.PropertyOption`: Returns required/optional option

### 6. Removed Deprecated Functions

Removed old Janus-specific functions:
- `janusReqToMcpReq()`
- `mcpParamToJanusParam()`
- `getProp()`

### 7. Added Tests

Created `cmd/mcp-server_test.go` with TDD tests:
- `TestMCPServerPluginRegistry`: Verifies registry iteration
- `TestMCPToolConversion`: Verifies plugin-to-MCP conversion

Created `cmd/mcp_integration_test.go`:
- `TestMCPServerCanAccessRegistry`: Integration test for registry access

## Verification

✅ **Build succeeds:**
```bash
go build -o /tmp/nebula .
```

✅ **MCP server command works:**
```bash
/tmp/nebula mcp-server --help
```

✅ **No compilation errors related to:**
- `recon.AWSPublicResources` (removed)
- `registry.GetRegistryEntry()` (replaced with `plugin.Get()`)
- Old Janus imports (removed)

## Migration Path

Modules now register themselves via `init()` functions:

```go
package recon

import "github.com/praetorian-inc/diocletian/pkg/plugin"

func init() {
    plugin.Register(&FindSecretsResource{})
}

type FindSecretsResource struct{}

func (m *FindSecretsResource) ID() string { return "find-secrets-resource" }
func (m *FindSecretsResource) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *FindSecretsResource) Category() plugin.Category { return plugin.CategoryRecon }
// ... other interface methods
```

The MCP server now automatically discovers all registered modules at runtime.

## Known Issues

The file `cmd/generator_integration_test.go` has unrelated compilation errors due to deprecated `chain.Module` references. This is outside the scope of the MCP server fix and should be addressed separately.

## Future Improvements (TODOs in code)

1. **Optimize module lookup**: Add reverse index (ID → Module) to avoid nested loops
2. **Structured output**: Support JSON output format in addition to text
3. **Tool name prefixing**: Add "nebula-platform-" prefix to tool names (line 44 comment)
4. **Verbose flag**: Extract and use verbose flag from MCP request (line 114)
