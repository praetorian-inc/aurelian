# Phase 3: Outputter Migration - COMPLETE

**Date:** 2026-02-04
**Status:** ✅ COMPLETE

## Summary

All 15 outputter files successfully migrated from Janus framework to native plugin system.

## Files Migrated (Final 3)

### 1. neo4j_graph_outputter.go
- **Removed:** `*chain.BaseOutputter`, `Params()` method
- **Added:** `cfg plugin.Config` field, `Initialize(cfg plugin.Config) error`
- **Changed:** `NewNeo4jGraphOutputter()` returns `*Neo4jGraphOutputter`
- **Pattern:** Uses `plugin.GetArgOrDefault()` for all config access

### 2. risk_csv_outputter.go
- **Removed:** `*chain.BaseOutputter`, `Params()` method
- **Added:** `cfg plugin.Config` field, `Initialize(cfg plugin.Config) error`
- **Changed:** `NewRiskCSVOutputter()` returns `*RiskCSVOutputter`
- **Pattern:** Simple CSV outputter with config-driven filename

### 3. runtime_json.go
- **Removed:** `*chain.BaseOutputter` (inherited via BaseFileOutputter), `Params()` method
- **Added:** `cfg plugin.Config` field, `Initialize(cfg plugin.Config) error`
- **Changed:** `NewRuntimeJSONOutputter()` returns `*RuntimeJSONOutputter`
- **Pattern:** Complex outputter with platform-specific filename generation
- **Special:** Uses `cfg.Has("profile")` to check parameter existence before access

## Verification

```bash
# Zero Janus imports remaining
grep -r "janus-framework" pkg/outputters/ | wc -l
# Output: 0

# All 17 outputter files accounted for
ls -1 pkg/outputters/*.go | wc -l
# Output: 17
```

## Complete Outputter List (All Migrated)

1. ✅ arg_scan_output.go
2. ✅ azure_resource_outputter.go
3. ✅ base_file.go
4. ✅ erd_console.go
5. ✅ formatter_adapter.go
6. ✅ formatter_adapter_test.go
7. ✅ markdown_table_console.go
8. ✅ neo4j_graph_outputter.go (Phase 3 final)
9. ✅ np_findings_console.go
10. ✅ raw_output.go
11. ✅ raw_output_test.go
12. ✅ risk_console_outputter.go
13. ✅ risk_csv_outputter.go (Phase 3 final)
14. ✅ runtime_json.go (Phase 3 final)
15. ✅ runtime_markdown.go
16. ✅ screenshot_outputter.go
17. ✅ url_console.go

## Migration Pattern (Used for Final 3)

### Remove:
- `import "github.com/praetorian-inc/janus-framework/pkg/chain"`
- `import "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"`
- `*chain.BaseOutputter` embedding
- `Params()` method

### Add:
- `import "github.com/praetorian-inc/aurelian/pkg/plugin"`
- `cfg plugin.Config` field
- Change `Initialize()` to `Initialize(cfg plugin.Config) error`

### Replace:
- `cfg.As[T](o.Arg("param"))` → `plugin.GetArgOrDefault(o.cfg, "param", defaultValue)`
- `chain.Outputter` return type → `*ConcreteType`
- Constructor signature: `func New...() *ConcreteType` (no configs param)

## Key Learnings

### RuntimeJSONOutputter Complexity
- Most complex outputter due to platform-specific filename generation
- Required `cfg.Has("profile")` pattern to check parameter existence
- Multiple platform checks (AWS, Azure, GCP, Azure DevOps)
- Inherited from BaseFileOutputter (also migrated in Phase 3)

### Neo4jGraphOutputter
- Graph database integration with Konstellation
- Batch processing of nodes and relationships
- Account enrichment queries
- Connection validation with graceful degradation

### RiskCSVOutputter
- Simplest of the three
- Collects risks in memory, writes on Complete()
- Configurable output filename

## Next Steps (Recommended)

1. **Phase 4: Links Migration** (49 files in `pkg/links/`)
   - ~95 files import janus-framework
   - Core business logic implementations
   - Most critical phase

2. **Phase 5: Registry Cleanup** (`internal/registry/`)
   - Delete old Janus chain registration system
   - Only new plugin registry should exist

3. **Phase 6: Documentation Update**
   - README.md still says "built on Janus"
   - Update architecture docs

4. **Phase 7: Final Verification**
   - `grep -r "janus-framework" .` should be empty
   - Remove from go.mod
   - Full test suite

## Progress Update

- **Phase 1:** ✅ Plugin foundation (5 files)
- **Phase 2:** ✅ CLI integration (3 files)
- **Phase 3:** ✅ Outputters (15 files) - **COMPLETE**
- **Phase 4:** ❌ Links (~95 files) - **REMAINING**
- **Phase 5:** ❌ Registry cleanup
- **Phase 6:** ❌ Documentation
- **Phase 7:** ❌ Final verification

**Completion:** ~26% → ~30% (15 more files migrated)

**Estimated Remaining:** 35-45 hours (Phase 4 is largest)
