# Comprehensive Code Review: Aurelian

**Review Date**: 2026-02-04
**Reviewer**: Claude Code
**Historical Note**: This tool was formerly known as "nebula" and then "diocletian" before being renamed to "aurelian".
**Context**: Nathan performed the initial refactor of nebula (renamed to diocletian, now aurelian). Further refactoring was required to remove janus-framework from the control flow, remove tabularium, and simplify module architecture.

---

## Executive Summary

| Dependency | Status | Evidence |
|------------|--------|----------|
| **Tabularium** | ✅ Decoupled | Transitive only (`// indirect` in go.mod:136), own types defined |
| **Janus Framework** | ❌ **Deeply Bounded** | Direct dependency (go.mod:64), 40+ files, core of architecture |

---

## Tabularium: Successfully Removed

The refactoring goal for tabularium has been **achieved**:
- `go.mod:136` shows: `github.com/praetorian-inc/tabularium v1.0.7-pre-prod // indirect`
- Aurelian defines its own universal types in `pkg/output/types.go`:
  - `CloudResource` (replaces any tabularium asset types)
  - `Risk` (replaces any tabularium risk types)
  - `SecretFinding` (native type)

**Evidence**:
- 281 Go files searched - NO direct tabularium imports found
- Only reference to "tabularium" is in test mocks for org names

---

## Janus Framework: NOT Removed - Deeply Embedded

The goal to "remove janus-framework from the control flow" has **NOT been achieved**. The entire architecture is built on janus-framework:

### Structural Coupling (Every Component)

**Note**: References to "diocletian" below are preserved as historical documentation of the codebase at time of review (2026-02-04), before rename to "aurelian".

```
┌────────────────────────────────────────────────────────────────────┐
│                    JANUS FRAMEWORK COUPLING                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  MODULES (47 total)                                                │
│  ├── chain.NewModule()           ← All modules use this           │
│  ├── cfg.NewMetadata()           ← All metadata uses this         │
│  ├── .WithLinks()                ← Links chain from janus         │
│  ├── .WithOutputters()           ← Outputters from janus          │
│  ├── .WithParams()               ← cfg.NewParam from janus        │
│  └── .WithConfigs()              ← cfg.WithArg from janus         │
│                                                                    │
│  LINKS (processing units)                                          │
│  ├── chain.Link interface        ← Every link implements this     │
│  ├── chain.Base embedded         ← Every link embeds this         │
│  ├── l.Send()                    ← Output method from chain.Base  │
│  ├── l.Arg()                     ← Config access from chain.Base  │
│  └── l.Logger                    ← Logging from chain.Base        │
│                                                                    │
│  OUTPUTTERS                                                        │
│  ├── chain.Outputter interface   ← All outputters implement this  │
│  └── chain.BaseOutputter         ← Common functionality           │
│                                                                    │
│  CONFIG SYSTEM                                                     │
│  ├── cfg.Param                   ← Type-safe parameter definition │
│  ├── cfg.Config                  ← Runtime configuration          │
│  ├── cfg.As[T]()                 ← Generic type extraction        │
│  └── cfg.ContextHolder           ← State management               │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Code Evidence

**Module Definition** (pkg/modules/aws/recon/whoami.go:16-39):
```go
var AwsWhoami = chain.NewModule(          // ← janus-framework
    cfg.NewMetadata(...),                  // ← janus-framework
).WithLinks(
    aws.NewAwsWhoami,
).WithOutputters(
    outputters.NewRuntimeJSONOutputter,
).WithParams(
    cfg.NewParam[string](...),             // ← janus-framework
).WithConfigs(
    cfg.WithArg(...),                      // ← janus-framework
).WithAutoRun()
```

**Link Base Class** (pkg/links/aws/base/aws_recon_base_link.go:17-27):
```go
type AwsReconBaseLink struct {
    *chain.Base                            // ← janus-framework embedded
    Profile    string
    ProfileDir string
}

func NewAwsReconBaseLink(link chain.Link, configs ...cfg.Config) *AwsReconBaseLink {
    a := &AwsReconBaseLink{}
    a.Base = chain.NewBase(link, configs...)  // ← janus-framework
    return a
}
```

**Link Implementation** (pkg/links/aws/whoami.go:23-28):
```go
func NewAwsWhoami(configs ...cfg.Config) chain.Link {  // ← returns janus type
    link := &AwsWhoami{}
    link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
    link.Base.SetName("AWS Covert Whoami")
    return link
}
```

### Import Analysis

**Core Imports** (found in 40+ files):
```go
import (
    "github.com/praetorian-inc/janus-framework/pkg/chain"              // Module, Link classes
    "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"          // Config/Param system
    "github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"  // Secret scanning
    "github.com/praetorian-inc/janus-framework/pkg/links/docker"       // Container analysis
    "github.com/praetorian-inc/janus-framework/pkg/output"             // Output writer interface
    "github.com/praetorian-inc/janus-framework/pkg/types"              // Common types
)
```

---

## What Would Be Required to Remove Janus Framework

To achieve the stated goal of "removing janus-framework from control flow", you would need to:

### 1. Define Native Interfaces (~200 lines)
- `Module` interface
- `Link` interface
- `Outputter` interface
- `Param` and `Config` types

### 2. Implement Native Base Classes (~500 lines)
- `BaseLink` with `Send()`, `Arg()`, logging
- `BaseOutputter` with common output logic
- Pipeline execution engine

### 3. Migrate All 47 Modules (~3000+ lines changed)
- Replace `chain.NewModule()` with native builder
- Update all `cfg.*` references

### 4. Migrate All Links (~8000+ lines changed)
- Remove `chain.Base` embedding
- Implement native parameter handling
- Update all `l.Send()`, `l.Arg()` calls

### 5. Migrate All Outputters (~2000+ lines changed)
- Replace `chain.Outputter` interface
- Update output dispatching

**Estimated effort**: Significant refactoring (13,000+ lines of code changes)

---

## Dependency Tree

```
aurelian (formerly diocletian/nebula)
├── janus-framework (Direct) ❌ STILL BOUNDED
│   ├── tabularium (Transitive - NOT used by aurelian)
│   ├── neo4j-go-driver (Transitive)
│   └── [other transitive dependencies]
├── capability-sdk (Direct - Local replacement)
├── konstellation (Direct)
├── AWS SDK v2 (Direct - 15+ service clients)
├── Azure SDK (Direct - 10+ service clients)
├── Google Cloud SDK (Direct - 5+ service clients)
└── [Open source: cobra, docker, mcp-go, etc.]

No circular dependencies detected.
```

---

## Assessment Summary

| Refactoring Goal | Status | Notes |
|------------------|--------|-------|
| Remove tabularium | ✅ **Done** | Transitive only, own types defined in `pkg/output/types.go` |
| Remove janus-framework | ❌ **Not Done** | Core of architecture, 40+ files affected |
| Simplify module architecture | ⚠️ **Partially** | Clean patterns but janus dependency remains |
| Resume scan feature | ❓ **Unknown** | Needs separate review |
| Tool rename (nebula → diocletian → aurelian) | ✅ **Done** | Renamed 2026-02-04 |

---

## Recommendations

### Option A: Accept Janus Dependency
If janus-framework is stable and maintained, the current architecture is functional and well-organized. The dependency provides:
- Type-safe parameter system
- Clean module composition pattern
- Tested pipeline execution
- Consistent outputter interface

### Option B: Full Decoupling (Major Effort)
If complete independence is required:
1. Fork/inline the ~2000 lines of janus-framework that aurelian (formerly diocletian) actually uses
2. Gradually migrate modules to native implementations
3. Remove janus-framework dependency

### Option C: Partial Decoupling
Extract only the core interfaces into a local package while keeping janus-framework for complex functionality:
1. Define local `Module`, `Link`, `Outputter` interfaces
2. Create adapters to janus-framework implementations
3. Gradually migrate to native implementations

---

## Files Reviewed

- `go.mod` - Dependency declarations
- `main.go` - Entry point
- `cmd/root.go` - CLI setup
- `cmd/generator.go` - Dynamic CLI generation
- `internal/registry/registry.go` - Module registration
- `pkg/output/types.go` - Universal output types
- `pkg/outputters/formatter_adapter.go` - capability-sdk bridge
- `pkg/links/aws/base/aws_recon_base_link.go` - Base link class
- `pkg/links/aws/whoami.go` - Example link implementation
- `pkg/modules/aws/recon/whoami.go` - Example module definition
- 281 Go files searched for dependency analysis
