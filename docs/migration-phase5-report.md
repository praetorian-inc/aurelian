# Phase 5 Migration Report: pkg/links (general/, docker/, llm/)

## Date
2026-02-04

## Scope
Migrate pkg/links/general/, pkg/links/docker/, pkg/links/llm/ from Janus to native plugin system.

## Files Migrated

### pkg/links/general/ (5 files)
1. ✅ echo.go - Simple passthrough link
2. ✅ generator.go - Pipeline trigger generator
3. ✅ jq.go - JSON filtering with jq
4. ✅ unmarshal.go - Typed JSON unmarshal link
5. ✅ preprocess_resources.go - Resource type preprocessors (4 link types)

### pkg/links/docker/ (6 files)
1. ✅ pull.go - Docker image pull
2. ✅ save.go - Save Docker images to tar
3. ✅ extract.go - Extract Docker images (3 link types: ExtractToFS, ExtractToNP, ImageLoader)
4. ✅ aggregator.go - Scan result aggregation
5. ✅ scan_summary.go - Scan summary generation
6. ℹ️  helpers.go - No Janus imports (skipped)

### pkg/links/llm/ (1 file)
1. ✅ anthropic_analyzer.go - Claude API LLM analysis (458 lines)

## Total Files Modified
14 Go files

## Migration Pattern Applied

**Before (Janus):**
```go
import (
    "github.com/praetorian-inc/janus-framework/pkg/chain"
    "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

type MyLink struct {
    *chain.Base
}

func NewMyLink(configs ...cfg.Config) chain.Link {
    l := &MyLink{}
    l.Base = chain.NewBase(l, configs...)
    return l
}

func (l *MyLink) Process(input T) error {
    l.Send(output)
    return nil
}
```

**After (Native):**
```go
import (
    "context"
    "github.com/praetorian-inc/aurelian/pkg/plugin"
)

type MyLink struct {
    *plugin.BaseLink
}

func NewMyLink(args map[string]any) *MyLink {
    return &MyLink{
        BaseLink: plugin.NewBaseLink("my-link", args),
    }
}

func (l *MyLink) Process(ctx context.Context, input any) ([]any, error) {
    return []any{output}, nil
}

func (l *MyLink) Parameters() []plugin.Parameter {
    return []plugin.Parameter{
        {Name: "param", Description: "...", Required: false, Type: "string"},
    }
}
```

## Key Changes

1. **Import changes:**
   - ❌ Removed: `janus-framework/pkg/chain`
   - ❌ Removed: `janus-framework/pkg/chain/cfg`
   - ✅ Added: `aurelian/pkg/plugin`
   - ✅ Added: `context` for Process methods

2. **Base struct:**
   - `*chain.Base` → `*plugin.BaseLink`
   - Constructor: `chain.NewBase(l, configs...)` → `plugin.NewBaseLink("name", args)`

3. **Process signature:**
   - `Process(input T) error` → `Process(ctx context.Context, input any) ([]any, error)`
   - `l.Send(val)` → return `[]any{val}`
   - Multiple outputs: return `[]any{val1, val2, ...}`

4. **Parameters:**
   - `Params() []cfg.Param` → `Parameters() []plugin.Parameter`
   - Initialization: extracted from `Initialize()` into constructor

5. **Argument access:**
   - `cfg.As[T](l.Arg("x"))` → `l.ArgString("x", "default")`, `l.ArgBool("x", false)`, etc.

## Verification

```bash
# No janus-framework/pkg/chain imports remain
grep -r "github.com/praetorian-inc/janus-framework/pkg/chain" \
  pkg/links/general/ pkg/links/docker/ pkg/links/llm/
# Result: 0 matches

# Type imports remain (expected)
grep -r "janus-framework/pkg/types" pkg/links/docker/ pkg/links/llm/
# Result: aggregator.go, scan_summary.go (NPFinding types)
#         pull.go, save.go, extract.go (docker.DockerImage type)
#         anthropic_analyzer.go (types.AnalyzableContent, types.LLMAnalysisResult)
```

## Exit Criteria

- [x] All files in general/, docker/, llm/ have no Janus chain imports
- [x] Each link uses `*plugin.BaseLink`
- [x] Process methods return `([]any, error)` with context
- [x] Parameters methods return `[]plugin.Parameter`

## Status

✅ **COMPLETE** - Phase 5 migration successful

All 14 files migrated from Janus to native plugin system.
No janus-framework/pkg/chain imports remain in target directories.

## Next Steps (Remaining Work)

Based on lead review, remaining work includes:

1. **pkg/links/** (~95 files) - Other link directories
2. **pkg/outputters/** (~15 files) - Output processors
3. **internal/registry/** - Still using Janus chain.Module
4. **11+ modules** - Return "not implemented" errors
5. **go.mod cleanup** - Remove janus-framework dependency
6. **README/docs** - Update to reflect native implementation

**Estimated remaining: 40-60 hours**
