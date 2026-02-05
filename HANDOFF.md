# aurelian CLI Migration - Handoff Document

**Project:** Migrate aurelian to standalone CLI pattern
**Current Phase:** Phase 0 COMPLETE (Standalone CLI ready)
**Next Task:** Phase 0, Task 3 - Create Chariot parser library (for integration)

---

## Quick Start for Continuing Work

### 1. Understand the Goal

Transform aurelian from:
```go
// BEFORE: Chariot imports aurelian as library
import aurelianMods "github.com/praetorian-inc/aurelian/pkg/modules"
mod := aurelianMods.AWSPublicResourcesSingle
mod.Run(cfg)
```

To:
```bash
# AFTER: Chariot invokes aurelian as CLI
aurelian aws public-resources --profile prod --output-format json | chariot-parser
```

### 2. Read Key Documents

1. **Master Plan:** `.claude/.output/capabilities/20260104-195038-aurelian-refactoring-analysis/MASTER-REFACTORING-PLAN.md`
2. **Architecture Q&A:** `.claude/.output/capabilities/20260104-195038-aurelian-refactoring-analysis/ARCHITECTURE-QA.md`
3. **This status:** `modules/aurelian/STATUS.md`

### 3. Verify Current State

```bash
cd modules/aurelian

# Should return EMPTY (no Tabularium imports)
grep -r "tabularium" pkg --include="*.go" | grep -v "_test.go"

# Should PASS
go build ./...
```

---

## Architecture Overview

### Pure CLI Pattern (Option A)

```
┌─────────────────┐     NDJSON      ┌─────────────────┐
│   aurelian CLI    │ ──────────────> │   Chariot       │
│                 │   Pure Domain   │   Parser        │
│ NO Neo4j keys   │   Data          │ Generates keys  │
│ NO Tabularium   │                 │ Creates models  │
└─────────────────┘                 └─────────────────┘
```

### Key Types

**aurelian outputs** (`pkg/output/`):
```go
type CloudResource struct {
    Platform     string            `json:"platform"`      // "aws"
    ResourceType string            `json:"resource_type"` // "AWS::S3::Bucket"
    ResourceID   string            `json:"resource_id"`   // ARN
    AccountRef   string            `json:"account_ref"`   // Account ID
    // ... NO GetKey() method
}

type IAMPermission struct {
    Source     ResourceRef `json:"source"`
    Target     ResourceRef `json:"target"`
    Permission string      `json:"permission"`
    // ... NO pre-computed keys
}
```

**Chariot generates keys:**
```go
func generateKey(ref ResourceRef) string {
    return fmt.Sprintf("#%sresource#%s#%s", ref.Platform, ref.Account, ref.ID)
}
```

---

## Completed Tasks

### Task 2: Add JSON CLI Output Mode ✅

**Completed:** 2026-01-04

**What was built:**
- `cmd/root.go` - Added `--output-format` flag (line 47)
- `pkg/outputters/json_stream.go` - JSONStreamOutputter (46 lines)
- `pkg/outputters/json_stream_test.go` - Test suite (TDD verified)

### Task 2b: Wire Outputter to CLI Flag ✅

**Completed:** 2026-01-05

**What was built:**
- `cmd/output_selector.go` - Format selection logic with constants
- `cmd/generator.go` - Modified `runModule()` to wire outputters + `runChainWithInput()` helper
- `janus-framework/pkg/chain/module.go` - Added `Configs()` accessor
- `cmd/output_selector_test.go` - 6 unit tests
- `cmd/generator_integration_test.go` - 7 integration tests

**How it works:**
```go
// In runModule()
c := module.New()                              // Get chain from module
if outputterConstructor != nil {
    c = c.WithOutputters(outputterConstructor())  // Override outputters
}
c.WithConfigs(append(module.Configs(), configs...)...)  // Apply configs
runChainWithInput(c, module)                   // Execute chain
```

**aurelian is now standalone-ready:** `aurelian aws recon list --output-format json` outputs NDJSON to stdout.

---

## Next Tasks

### Task 3: Create Chariot Parser Library

**Goal:** Parse aurelian JSON output and convert to Tabularium types

**Location:** `modules/chariot/backend/pkg/lib/aurelian_cli/`

**Files to create:**

1. `types.go` - Mirror aurelian's output types
2. `parser.go` - Parse NDJSON, convert to Tabularium
3. `relationships.go` - Convert IAMPermission to model.IAMRelationship
4. `parser_test.go` - Tests

**Key function:**
```go
func ParseResources(data []byte) ([]model.Assetlike, error) {
    scanner := bufio.NewScanner(bytes.NewReader(data))
    var results []model.Assetlike

    for scanner.Scan() {
        var nr aurelianResource
        json.Unmarshal(scanner.Bytes(), &nr)

        // Generate key HERE (not in aurelian)
        key := generateKey(nr.Platform, nr.AccountRef, nr.ResourceID)

        // Convert to Tabularium type
        resource := model.NewAWSResource(...)
        results = append(results, resource)
    }
    return results, nil
}
```

---

## File Locations

### aurelian (this repo)
```
modules/aurelian/
├── cmd/                          # CLI commands
├── pkg/
│   ├── output/
│   │   ├── types.go              # CloudResource, Risk, SecretFinding
│   │   ├── types_test.go         # 7 tests
│   │   ├── relationships.go      # IAMPermission, ResourceRef, etc.
│   │   └── relationships_test.go # 11 tests
│   ├── links/
│   │   ├── gcp/                  # ✅ Migrated (11 files)
│   │   ├── azure/                # ✅ Migrated (27 files)
│   │   └── aws/                  # ✅ Migrated (all files)
│   ├── outputters/               # ✅ Migrated (6 files)
│   └── modules/                  # Module definitions
├── STATUS.md                     # This file
└── HANDOFF.md                    # You are here
```

### Chariot (for Task 3+)
```
modules/chariot/backend/
├── pkg/
│   ├── lib/
│   │   └── aurelian_cli/           # TO CREATE
│   │       ├── types.go
│   │       ├── parser.go
│   │       ├── relationships.go
│   │       └── parser_test.go
│   └── tasks/
│       └── capabilities/
│           └── aurelian_*/         # Capability wrappers (Phase 1)
```

---

## Common Patterns

### Resource Type Mapping

| Tabularium Constant | Pure CLI String |
|---------------------|-----------------|
| `tab.GCPResourceProject` | `"cloudresourcemanager.googleapis.com/Project"` |
| `tab.AWSResourceS3Bucket` | `"AWS::S3::Bucket"` |
| `tab.AzureResourceStorageAccount` | `"Microsoft.Storage/storageAccounts"` |

### Field Mapping

| Tabularium | Pure CLI |
|------------|----------|
| `resource.Name` | `resource.ResourceID` |
| `resource.AccountID` | `resource.AccountRef` |
| `risk.Severity()` | `risk.Status` |
| `resource.GetIPs()` | `resource.IPs` |

---

## Troubleshooting

### Build fails after migration

```bash
# Check for remaining Tabularium imports
grep -r "tabularium" pkg --include="*.go"

# Common issues:
# 1. Forgot to update function signature
# 2. Method call on struct that's now a field (e.g., Severity() → Status)
# 3. Interface implementation changed
```

### Tests fail

```bash
# Run specific package tests
go test ./pkg/output/... -v

# Check for type mismatches in assertions
```

### Neo4j keys don't match

Keys are generated in Chariot parser, not aurelian. Format:
```
#awsresource#{account}#{arn}
#azureresource#{subscription}#{resource_id}
#gcpresource#{project}#{resource_path}
```

---

## Agent Instructions

When continuing this work with Claude Code agents:

**For Task 3 (Chariot parser):**
```
Use backend-developer agent
Mandatory skills: developing-with-tdd, gateway-backend, verifying-before-completion
Output directory: .claude/.output/capabilities/20260104-195038-aurelian-refactoring-analysis/
```

**For Phase 1 (Capability wrappers):**
```
Use capability-developer agent
Mandatory skills: developing-with-tdd, gateway-capabilities, verifying-before-completion
Output directory: .claude/.output/capabilities/20260104-195038-aurelian-refactoring-analysis/
```

---

## Contact & Resources

- **Master Plan:** `.claude/.output/capabilities/20260104-195038-aurelian-refactoring-analysis/MASTER-REFACTORING-PLAN.md`
- **Architecture Decision:** Pure CLI (Option A) per `ARCHITECTURE-QA.md`
- **Reference Implementations:** `fingerprintx`, `go-cicd`, `nuclei`
