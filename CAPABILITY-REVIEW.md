# Aurelian Security Modules - Capability Assessment

**Date:** 2026-02-04
**Reviewer:** capability-lead (Claude)
**Assessment Type:** Architecture Review
**Rating:** INCOMPLETE MIGRATION - CHANGES REQUIRED

---

## Executive Summary

The Aurelian codebase represents a **partially completed migration** from the Janus framework to a native Go plugin architecture. While the core `pkg/plugin/` foundation has been properly implemented with correct patterns, the migration is **far from complete**:

- **49 modules** have been created implementing `plugin.Module` interface
- **144 Go files** still import from `janus-framework`
- **11+ modules** have incomplete implementations (return "not implemented" errors)
- The `internal/registry/registry.go` still uses Janus `chain.Module` type

**Verdict:** The migration architecture is sound, but execution is incomplete. Approximately 60-70% of the work remains.

---

## Rating Summary

| Aspect | Rating | Justification |
|--------|--------|---------------|
| Plugin Interface Design | GOOD | Clean `plugin.Module` interface with proper methods |
| Registry Implementation | GOOD | Thread-safe with `sync.RWMutex`, factory pattern |
| Janus Removal | CRITICAL | 144 files still import janus-framework |
| Module Implementation | MIXED | 49 modules exist, 11+ incomplete |
| Pattern Consistency | GOOD | AWS/Azure/GCP follow same patterns |
| Credential Handling | GOOD | No password/secret logging found |
| Dead/Incomplete Code | HIGH | Multiple modules return stub errors |

**Overall:** CHANGES REQUIRED - Cannot ship until Janus removal complete

---

## Detailed Findings

### 1. Plugin Interface Compliance

**Location:** `pkg/plugin/module.go`

The `plugin.Module` interface is well-designed:

```go
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

**Assessment:** COMPLIANT with Go plugin registry patterns from `implementing-go-plugin-registries` skill.

**Evidence:**
- Thread-safe `sync.RWMutex` in registry
- Factory pattern via init() self-registration
- Proper hierarchy map for CLI generation

### 2. Remaining Janus Imports (CRITICAL ISSUE)

**Finding:** 144 Go files still import from `github.com/praetorian-inc/janus-framework`

**Critical Files:**
- `internal/registry/registry.go` - Uses `chain.Module` type (line 9)
- All files in `pkg/links/` directories
- All files in `pkg/outputters/`
- Various test files

**Evidence:**
```
grep -r "janus-framework" --include="*.go" | wc -l
Result: 144 files
```

**Impact:**
- Prevents standalone deployment
- Creates dependency conflicts
- Violates migration goals

**Recommendation:** Complete removal of all janus-framework imports is REQUIRED before this can be considered migration-complete.

### 3. Module Counts by Platform

| Platform | Category | Module Count | Status |
|----------|----------|--------------|--------|
| AWS | recon | 17 | Mostly complete |
| AWS | analyze | 5 | Complete |
| Azure | recon | 9 | 4+ incomplete |
| GCP | recon | 9 | Complete |
| GCP | secrets | 6 | 5+ incomplete |
| SaaS | recon | 1 | Incomplete |
| **TOTAL** | | **49** | **11+ incomplete** |

### 4. Incomplete Module Implementations

The following modules return errors indicating they need migration:

| Module | Platform | File | Issue |
|--------|----------|------|-------|
| docker-dump | SaaS | `saas/recon/docker_dump.go` | 4 helper functions return "not implemented" |
| arg-scan | Azure | `azure/recon/arg_scan.go` | Returns "module implementation pending" |
| find-secrets | AWS | `aws/recon/find_secrets.go` | Returns "module implementation pending" |
| find-secrets | Azure | `azure/recon/find_secrets.go` | TODO: Implement full workflow |
| find-secrets-resource | Azure | `azure/recon/find_secrets_resource.go` | TODO: Implement logic |
| find-secrets-resource | AWS | `aws/recon/find_secrets_resource.go` | Implementation pending |
| ecr-dump | AWS | `aws/recon/ecr_dump.go` | TODO: Implement ECR dump |
| role-assignments | Azure | `azure/recon/role_assignments.go` | TODO: Implement |
| summary | Azure | `azure/recon/summary.go` | TODO: Implement |
| scan-storage | GCP | `gcp/secrets/scan_storage.go` | 5 functions return "not implemented" |
| apollo-offline | AWS | `aws/recon/apollo_offline.go` | TODO: Neo4j relationship creation |

### 5. Architecture Pattern Compliance

**Positive Findings:**

1. **Consistent Module Structure:** All modules follow the same pattern:
   - `func init() { plugin.Register(&ModuleName{}) }`
   - Struct with receiver methods for all interface methods
   - Parameters() returns proper `[]plugin.Parameter` slices

2. **Thread-Safe Registry:** `pkg/plugin/registry.go` properly implements:
   - `sync.RWMutex` for concurrent access
   - Factory pattern (new instance per Get())
   - Sorted listing capability

3. **Platform/Category Hierarchy:** Proper organization under:
   - `pkg/modules/aws/recon/`
   - `pkg/modules/aws/analyze/`
   - `pkg/modules/azure/recon/`
   - `pkg/modules/gcp/recon/`
   - `pkg/modules/gcp/secrets/`
   - `pkg/modules/saas/recon/`

**Negative Findings:**

1. **Dual Registry:** Two registry implementations exist:
   - `pkg/plugin/registry.go` - New native registry (correct)
   - `internal/registry/registry.go` - Old Janus-based registry (should be removed)

2. **Links Still Use Janus:** All files in `pkg/links/` use Janus `chain.Link` pattern

### 6. Parameter Definitions Review

**Sample Module Parameters (AWS List):**
```go
func (m *AWSListResourcesModule) Parameters() []plugin.Parameter {
    return []plugin.Parameter{
        {
            Name:        "resource-type",
            Description: "AWS resource type (e.g., AWS::S3::Bucket)",
            Type:        "string",
            Required:    true,
        },
        {
            Name:        "region",
            Description: "AWS region",
            Type:        "string",
            Default:     "us-east-1",
        },
        // ...
    }
}
```

**Assessment:** Parameter definitions are consistent and well-structured across modules.

### 7. Credential Handling Security

**Verified Safe:**
- No passwords logged via `fmt.Print*`
- No secrets logged via `slog.*`
- Credentials passed as function parameters, not stored globally

**Example (docker-dump):**
```go
{
    Name:        "docker-password",
    Description: "Docker registry password (if authentication required)",
    Type:        "string",
    Required:    false,
    Default:     "",
}
```

The password is received via Config.Args and not logged.

---

## Critical Issues Requiring Resolution

### Issue 1: Janus Framework Dependency (BLOCKING)

**Severity:** CRITICAL

The `internal/registry/registry.go` still uses:
```go
import "github.com/praetorian-inc/janus-framework/pkg/chain"
```

And references:
```go
type RegistryEntry struct {
    Module          chain.Module  // <-- MUST be plugin.Module
    ModuleHeriarchy ModuleHeriarchy
}
```

**Resolution Required:**
1. Remove `internal/registry/` entirely OR
2. Migrate it to use `plugin.Module` instead of `chain.Module`

### Issue 2: Incomplete Module Implementations (BLOCKING)

**Severity:** HIGH

11+ modules return error messages indicating incomplete migration:
- "not implemented"
- "module implementation pending"
- "needs to be migrated from Janus chain/link architecture"

**Resolution Required:**
Port remaining Janus chain/link logic to native function calls within each module's `Run()` method.

### Issue 3: Links Directory Uses Janus (MAJOR)

**Severity:** HIGH

All files in `pkg/links/` import janus-framework:
- `pkg/links/aws/` - 40+ files
- `pkg/links/azure/` - 30+ files
- `pkg/links/gcp/` - 15+ files
- `pkg/links/docker/` - 7 files

**Resolution Required:**
Decide whether to:
1. Port link implementations to module Run() methods directly, OR
2. Create a new native pipeline pattern (pkg/plugin/processor.go exists but unused)

---

## Recommendations

### Immediate Actions (P0)

1. **Remove or migrate `internal/registry/registry.go`** to eliminate Janus chain.Module usage
2. **Complete the 11 incomplete modules** - they currently fail at runtime
3. **Update `cmd/module_imports.go`** to reference correct package paths

### Short-Term Actions (P1)

1. **Port `pkg/links/` to native implementations** - This is ~100 files of work
2. **Remove janus-framework from go.mod** once all imports are eliminated
3. **Add integration tests** for migrated modules

### Long-Term Actions (P2)

1. **Consider using pkg/plugin/processor.go Pipeline** for complex multi-step modules
2. **Document migration patterns** for future capability developers
3. **Add module validation tooling** to prevent shipping incomplete modules

---

## Migration Progress Summary

| Component | Files | Complete | Remaining |
|-----------|-------|----------|-----------|
| pkg/plugin/ (foundation) | 5 | 5 (100%) | 0 |
| pkg/modules/ (modules) | 48 | 37 (~77%) | 11 |
| pkg/links/ (links) | ~95 | 0 (0%) | ~95 |
| pkg/outputters/ | ~15 | 0 (0%) | ~15 |
| internal/registry/ | 1 | 0 (0%) | 1 |
| **TOTAL** | ~164 | ~42 (26%) | ~122 (74%) |

**Estimated Remaining Work:** 40-60 hours of development time

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "architecture-review",
  "timestamp": "2026-02-04T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/aurelian",
  "skills_invoked": [
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "gateway-backend",
    "reviewing-capability-implementations",
    "enforcing-go-capability-architecture",
    "implementing-go-plugin-registries",
    "adhering-to-dry",
    "adhering-to-yagni"
  ],
  "source_files_verified": [
    "pkg/plugin/module.go",
    "pkg/plugin/registry.go",
    "pkg/plugin/output.go",
    "pkg/plugin/processor.go",
    "internal/registry/registry.go",
    "cmd/module_imports.go",
    "go.mod",
    "STATUS.md",
    "pkg/modules/aws/recon/list.go",
    "pkg/modules/aws/recon/apollo.go",
    "pkg/modules/aws/recon/apollo_offline.go",
    "pkg/modules/azure/recon/arg_scan.go",
    "pkg/modules/gcp/recon/list_projects.go",
    "pkg/modules/saas/recon/docker_dump.go"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Complete Janus unbinding migration per recommendations above"
  }
}
```
