# Aurelian Native Plugin Architecture Review

**Date:** 2026-02-04
**Reviewer:** backend-lead
**Status:** CHANGES REQUESTED
**Overall Rating:** B- (Migration In Progress, Critical Issues Remain)

---

## Executive Summary

The Aurelian codebase has undergone a partial migration from the Janus framework to a native Go plugin architecture. The new `pkg/plugin/` package provides a clean, standalone plugin system. However, **the migration is incomplete** - the Janus framework dependency remains deeply embedded throughout the codebase, creating a dual architecture that increases complexity and maintenance burden.

---

## 1. Plugin Interface Design (pkg/plugin/module.go)

### Verified Implementation

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/module.go` (lines 56-72)

```go
// Module is the core interface that all Aurelian modules implement
type Module interface {
    // Metadata
    ID() string
    Name() string
    Description() string
    Platform() Platform
    Category() Category
    OpsecLevel() string
    Authors() []string
    References() []string

    // Parameters
    Parameters() []Parameter

    // Execution
    Run(cfg Config) ([]Result, error)
}
```

### Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Interface clarity | GOOD | 11 methods, single responsibility per method |
| Method count | GOOD | Not excessive - all methods serve distinct purposes |
| Return types | GOOD | Clean `[]Result, error` pattern |
| Config struct | GOOD | Well-designed with Context, Args, Output, Verbose |

### Strengths

1. **Single Run method** - Clean execution model vs Janus chain/link complexity
2. **Typed Platform/Category constants** - Type safety for module classification
3. **Result struct includes Error field** - Allows partial success reporting
4. **Parameters() returns slice** - Self-describing modules for CLI generation

### Issues

| Severity | Issue | Location |
|----------|-------|----------|
| MEDIUM | Missing Validate() method | module.go interface |
| LOW | No lifecycle hooks (Init/Cleanup) | module.go interface |

**Recommendation:** Consider adding `Validate(args map[string]any) error` for parameter validation before Run().

---

## 2. Thread-Safe Registry Implementation (pkg/plugin/registry.go)

### Verified Implementation

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/registry.go` (lines 15-54)

```go
type registry struct {
    mu        sync.RWMutex
    modules   map[string]RegistryEntry           // platform/category/id -> module
    hierarchy map[Platform]map[Category][]string // platform -> category -> []id
}

var Registry = &registry{
    modules:   make(map[string]RegistryEntry),
    hierarchy: make(map[Platform]map[Category][]string),
}

func Register(m Module) {
    Registry.mu.Lock()
    defer Registry.mu.Unlock()
    // ... registration logic with duplicate detection
}
```

### Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Thread safety | GOOD | RWMutex correctly used for read/write operations |
| Duplicate detection | GOOD | Panics on duplicate registration (fail-fast) |
| Hierarchy tracking | GOOD | O(1) lookups by platform/category |
| Global singleton | ACCEPTABLE | Standard pattern for init() registration |

### Strengths

1. **Proper RWMutex usage** - RLock for reads, Lock for writes
2. **GetHierarchy() returns copy** - Safe for concurrent iteration
3. **Composite key design** - `platform/category/id` enables efficient lookups

### Issues

| Severity | Issue | Location |
|----------|-------|----------|
| LOW | GetModuleByID() function missing | registry.go |
| LOW | No unregister functionality | registry.go |

**Recommendation:** Add `GetModuleByID(id string) (Module, bool)` for MCP server lookup optimization (see TODO in mcp-server.go:80).

---

## 3. Remaining Janus Framework References

### CRITICAL: Janus Dependency NOT Removed

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/go.mod` (line 64)
```
github.com/praetorian-inc/janus-framework v0.0.0-20250918211123-5f90adc9184b
```

### Files Still Using Janus Framework

**Total files with janus-framework imports:** 95+

| Category | File Count | Examples |
|----------|------------|----------|
| pkg/links/* | 70+ | All link implementations |
| pkg/outputters/* | 14 | All outputter implementations |
| internal/registry/ | 1 | Legacy registry still exists |
| cmd/root.go | 1 | cfg.LevelFromString import |
| cmd/generator_integration_test.go | 1 | Test still uses chain.NewModule |
| cmd/output_selector.go | 1 | Uses chain package |
| pkg/types/ | 1 | Uses jtypes for enriched_resource_description.go |
| test/links/* | 3 | Test files use janus imports |

### Modules NOT Migrated (Return Errors)

**Source:** Search for "pending" and "implementation pending"

| Module | File | Status |
|--------|------|--------|
| aws/recon/find-secrets | find_secrets.go:129 | Returns error: "needs to be migrated from Janus chain/link architecture" |
| aws/recon/ecr-dump | ecr_dump.go:110 | Returns error: "requires Janus link adapter pattern" |
| azure/recon/arg-scan | arg_scan.go:123 | Returns error: "needs to be migrated from Janus chain/link architecture" |
| azure/recon/summary | summary.go:92-106 | Returns placeholder data with "pending_implementation" |

### Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Migration completeness | POOR | <30% of modules fully migrated |
| Janus removal | NOT DONE | Still in go.mod, still imported in 95+ files |
| Dual architecture | CRITICAL | Two competing systems increase complexity |

---

## 4. Legacy Artifacts

### internal/registry Package (DEPRECATED BUT PRESENT)

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/internal/registry/registry.go`

This is the OLD Janus-based registry that uses `chain.Module` type. It should be removed but still exists:

```go
import "github.com/praetorian-inc/janus-framework/pkg/chain"

type RegistryEntry struct {
    Module          chain.Module  // OLD: Uses Janus type
    // ...
}
```

**Issue:** Two registries exist:
1. `internal/registry` - Old Janus-based (DEPRECATED)
2. `pkg/plugin` - New native plugin (CURRENT)

### Documentation Out of Date

| File | Issue |
|------|-------|
| README.md:3 | States "built on the Janus framework" |
| README.md:14 | Lists "Janus framework with composable links" |
| README.md:175 | Links to Janus Framework |
| DEVELOPMENT.md | Entire file documents Janus patterns |
| aurelian-janus-bounded.md | Documents that Janus "NOT removed" |

### No _v2 Suffix Artifacts

**Verified:** Grep for `_v2` found only one result in terraform test config (Standard_DS1_v2 VM size), not code artifacts. The migration appears to have cleaned up version suffixes properly.

---

## 5. Module Consistency Across Platforms

### Migrated Module Pattern (CORRECT)

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/aws/recon/whoami.go`

```go
func init() {
    plugin.Register(&AWSWhoamiModule{})
}

type AWSWhoamiModule struct{}

func (m *AWSWhoamiModule) ID() string          { return "whoami" }
func (m *AWSWhoamiModule) Platform() Platform  { return plugin.PlatformAWS }
func (m *AWSWhoamiModule) Run(cfg Config) ([]Result, error) { /* implementation */ }
```

### Module Inventory

| Platform | Migrated Modules | Implementation Status |
|----------|------------------|----------------------|
| AWS/recon | 17 files | Mixed (some return errors) |
| AWS/analyze | 5 files | Mostly complete |
| Azure/recon | 10 files | Mixed (some pending) |
| GCP/recon | 11 files | Mostly complete |
| GCP/secrets | 6 files | Complete |
| SaaS/recon | 1 file (docker_dump.go) | Pending implementation |

### main.go Blank Imports

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/main.go` (lines 10-16)

```go
// Import all modules to trigger init() registration
_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/analyze"
_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon"
_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/recon"
_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/secrets"
_ "github.com/praetorian-inc/aurelian/pkg/modules/saas/recon"
```

**Assessment:** Correct pattern for init() registration. All platform packages imported.

---

## 6. CLI Integration (cmd/)

### Generator Successfully Migrated

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/cmd/generator.go`

The CLI generator correctly uses `pkg/plugin` registry:
- Uses `plugin.GetHierarchy()` for command tree
- Uses `plugin.Get()` for module retrieval
- Uses `plugin.Config{}` for execution

### MCP Server Successfully Migrated

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/cmd/mcp-server.go`

The MCP server correctly uses `pkg/plugin` registry:
- Iterates `plugin.GetHierarchy()` for tool registration
- Converts `plugin.Module` to MCP tools
- Runs modules with `plugin.Config{}`

### Root Command Still Has Janus Import

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/cmd/root.go` (line 16)

```go
import "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
```

Used for log level configuration (lines 54-57). This could be replaced with native logging.

---

## 7. pkg/plugin/processor.go and pkg/plugin/output.go

### Pipeline Pattern (processor.go)

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/processor.go`

```go
// Pipeline chains multiple processors together
// This replaces the Janus chain.Link composition pattern
type Pipeline struct {
    processors []Processor
}
```

**Assessment:** GOOD design. Provides replacement for Janus chain.Link but NOT USED by any migrated modules yet.

### Output Formatters (output.go)

**Source:** `/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/output.go`

Provides JSONFormatter, ConsoleFormatter, MarkdownFormatter implementations.

**Assessment:** GOOD but underutilized. Most modules still rely on Janus outputters in `pkg/outputters/`.

---

## Summary of Issues

### CRITICAL

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| Janus framework not removed | Dual architecture, increased complexity | Complete migration or accept Janus dependency |
| 4+ modules return implementation errors | CLI commands fail | Implement or remove non-functional modules |
| internal/registry still exists | Confusion about which registry to use | Delete internal/registry package |

### HIGH

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| pkg/links/* still use Janus | 70+ files need migration | Migrate links to Pipeline pattern or accept dependency |
| pkg/outputters/* still use Janus | 14 files need migration | Migrate to pkg/plugin/output.go formatters |
| Documentation references Janus | Misleading documentation | Update README.md, DEVELOPMENT.md |

### MEDIUM

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| cmd/root.go imports janus cfg | Unnecessary Janus dependency | Replace with stdlib slog levels |
| No Module.Validate() method | Parameter validation done in Run() | Add Validate() to interface |
| MCP server module lookup is O(n) | Performance on large registry | Add GetModuleByID() to registry |

### LOW

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| Pipeline pattern unused | Dead code | Either use in migrations or document for future |
| Test files use Janus | Test maintenance | Update tests when modules migrate |

---

## Verdict

**CHANGES REQUESTED**

The native plugin architecture in `pkg/plugin/` is well-designed and correctly integrated into the CLI and MCP server. However, the migration is incomplete:

1. **Janus framework NOT removed** - Still in go.mod, imported in 95+ files
2. **4+ modules non-functional** - Return "pending implementation" errors
3. **Legacy registry exists** - internal/registry should be deleted
4. **Documentation misleading** - Still references Janus as the architecture

### Recommended Next Steps

1. **Decision Required:** Accept Janus dependency OR complete migration
   - If accepting: Document hybrid architecture, update README
   - If completing: Plan 35+ module migrations

2. **Immediate Cleanup:**
   - Delete `internal/registry/` package (unused)
   - Fix or remove non-functional modules (find-secrets, ecr-dump, arg-scan)
   - Update README.md to reflect current architecture

3. **If Continuing Migration:**
   - Migrate pkg/links/* to Pipeline pattern
   - Migrate pkg/outputters/* to pkg/plugin/output.go formatters
   - Remove janus-framework from go.mod

---

## Metadata

```json
{
  "agent": "backend-lead",
  "output_type": "architecture-review",
  "timestamp": "2026-02-04T00:00:00Z",
  "skills_invoked": [
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "behavior-first-architecture-analysis",
    "structuring-go-projects",
    "go-best-practices",
    "reviewing-backend-implementations",
    "adhering-to-dry",
    "verifying-before-completion"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/module.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/registry.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/output.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/processor.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/main.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/cmd/root.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/cmd/mcp-server.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/cmd/generator.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/internal/registry/registry.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/aws/recon/whoami.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/azure/recon/summary.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/gcp/recon/list_projects.go"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Complete Janus unbinding migration or document acceptance of hybrid architecture"
  }
}
```
