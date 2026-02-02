# Diocletian CLI Migration - Status Report

**Date:** 2026-01-04
**Project:** Migrate Diocletian from embedded library to standalone CLI
**Architecture:** Option A (Pure CLI) - Diocletian outputs domain data, Chariot handles graph concerns

---

## Executive Summary

Diocletian is being migrated from an embedded Go library pattern (imported by Chariot) to a standalone CLI tool pattern (invoked via `exec.Command`), matching `fingerprintx`, `nuclei`, and `go-cicd`.

**Current Status:** Phase 0 COMPLETE (Standalone CLI ready). Task 3 (Chariot parser) pending for integration only.

---

## Completed Work

### Phase 0, Task 1: Remove Tabularium Dependency ✅

| Milestone | Status | Files |
|-----------|--------|-------|
| Create native output types | ✅ Complete | `pkg/output/types.go` |
| Create relationship types (Pure CLI) | ✅ Complete | `pkg/output/relationships.go` |
| Migrate GCP packages | ✅ Complete | 11 files |
| Migrate Azure packages | ✅ Complete | 27 files |
| Migrate AWS CloudControl | ✅ Complete | 1 file (500+ resource types) |
| Migrate AWS Apollo IAM pipeline | ✅ Complete | 4 files |
| Migrate Outputters | ✅ Complete | 6 files |
| Remove Tabularium imports | ✅ Complete | 0 imports in production code |

**Key Achievement:** Diocletian production code has ZERO direct Tabularium imports.

### Phase 0, Task 2: Add JSON CLI Output Mode ✅

| Milestone | Status | Files |
|-----------|--------|-------|
| Add `--output-format` CLI flag | ✅ Complete | `cmd/root.go` |
| Create JSONStreamOutputter | ✅ Complete | `pkg/outputters/json_stream.go` |
| Write tests (TDD) | ✅ Complete | `pkg/outputters/json_stream_test.go` |

**Key Achievement:** NDJSON streaming outputter ready for module integration.

**Files Created:**
- `pkg/outputters/json_stream.go` - Streams NDJSON to stdout via `chain.Outputter` interface
- `pkg/outputters/json_stream_test.go` - Test suite (TDD verified)

**Note:** Module-level integration (wiring outputter into specific modules) deferred to capability migration phase.

### Phase 0, Task 2b: Wire Outputter to CLI Flag ✅

| Milestone | Status | Files |
|-----------|--------|-------|
| Create outputter selector | ✅ Complete | `cmd/output_selector.go` |
| Modify runModule() for outputter wiring | ✅ Complete | `cmd/generator.go` |
| Add Module.Configs() accessor | ✅ Complete | `janus-framework/pkg/chain/module.go` |
| Unit tests | ✅ Complete | `cmd/output_selector_test.go` |
| Integration tests | ✅ Complete | `cmd/generator_integration_test.go` |

**Key Achievement:** `--output-format json` now actually selects JSONStreamOutputter at runtime.

**Architecture:** Option 2 (Refined) - Chain-level outputter replacement without framework changes.

### Phase 0, Task 2c: P0 CLI Fixes ✅

| Milestone | Status | Files |
|-----------|--------|-------|
| GAP-001: Exit code handling | ✅ Complete | `main.go` |
| GAP-002: Messages to stderr | ✅ Complete | `internal/message/message.go` |
| GAP-003: Auto-quiet for JSON | ✅ Complete | `cmd/root.go` |

**Key Achievement:** Standalone CLI now properly returns exit codes, outputs messages to stderr, and auto-enables quiet mode for JSON format.

### New Types Created

**Domain Types** (`pkg/output/types.go`):
- `CloudResource` - Universal cloud resource (AWS/Azure/GCP)
- `SecretFinding` - Secret detection result
- `Risk` - Security finding/vulnerability

**Relationship Types** (`pkg/output/relationships.go`):
- `ResourceRef` - Resource identifier (NO Neo4j key knowledge)
- `IAMPermission` - IAM permission relationship
- `SSMPermission` - SSM-specific permission
- `GitHubActionsPermission` - OIDC federation
- `Repository` - Source code repository
- `ServicePrincipal` - AWS service principal

### Architecture Decision

**Option A (Pure CLI)** was chosen over Hybrid approach:

| Aspect | Hybrid (Rejected) | Pure CLI (Implemented) |
|--------|-------------------|------------------------|
| Neo4j key knowledge | In Diocletian (`GetKey()`) | In Chariot only |
| Output format | Pre-computed keys | Pure domain data |
| Standalone capability | Partial | Full |
| Matches fingerprintx/go-cicd | No | Yes |

---

## Remaining Work

### Phase 0, Task 3: Create Chariot Parser Library (Not Started)

**Objective:** Chariot-side parser to convert Diocletian JSON to Tabularium types

**Files to create:**
- `modules/chariot/backend/pkg/lib/diocletian_cli/types.go`
- `modules/chariot/backend/pkg/lib/diocletian_cli/parser.go`
- `modules/chariot/backend/pkg/lib/diocletian_cli/relationships.go`
- `modules/chariot/backend/pkg/lib/diocletian_cli/parser_test.go`

**Key responsibility:** Generate Neo4j keys from ResourceRef data
```go
func generateKey(ref ResourceRef) string {
    return fmt.Sprintf("#%sresource#%s#%s", ref.Platform, ref.Account, ref.ID)
}
```

**Estimated effort:** 3-4 hours

### Phase 1: Capability Wrapper Migration (Not Started)

**Objective:** Migrate Chariot capabilities from `mod.Run()` to `exec.Command("diocletian", ...)`

| Task | Capability | Priority | Coupling Score |
|------|------------|----------|----------------|
| 4 | diocletian_aws_public_resources | P0 | 9/10 |
| 5 | Feature flag for rollout | P0 | - |
| 6-13 | 8 P1 capabilities | P1 | 5-7/10 |

**Estimated effort:** 40-50 hours total

### Phase 2: Cleanup (Not Started)

**Objective:** Remove old embedded adapter layer from Chariot

**Files to delete:**
- `modules/chariot/backend/pkg/lib/diocletian/diocletian.go`
- `modules/chariot/backend/pkg/lib/diocletian/outputter.go`
- `modules/chariot/backend/pkg/lib/diocletian/azure.go`
- `modules/chariot/backend/pkg/lib/diocletian/noseyparker.go`
- `modules/chariot/backend/pkg/lib/diocletian/gcp-helpers.go`

**Estimated effort:** 2-4 hours

---

## Build Status

```bash
cd modules/diocletian
go build ./...   # ✅ PASSES
go test ./...    # ✅ PASSES (where tests exist)
```

**Tabularium in go.mod:** Retained as indirect dependency via janus-framework (expected)

---

## Test Coverage

| Package | Tests | Status |
|---------|-------|--------|
| `pkg/output/` | 18 tests | ✅ All passing |
| `pkg/outputters/` | 1 test (JSONStreamOutputter) | ✅ All passing |
| `cmd/` | 13 tests (outputter selection + integration) | ✅ All passing |
| `pkg/links/gcp/` | Existing tests | ✅ Passing |
| `pkg/links/azure/` | Existing tests | ✅ Passing |
| `pkg/links/aws/` | Existing tests | ✅ Passing |

---

## Documentation

All work documented in:
```
.claude/.output/capabilities/20260104-195038-diocletian-refactoring-analysis/
├── MASTER-REFACTORING-PLAN.md          # Original 4-agent consensus plan
├── IAM-RELATIONSHIP-ARCHITECTURE.md     # Hybrid architecture (superseded)
├── ARCHITECTURE-QA.md                   # Q&A leading to Pure CLI decision
├── OPTION-A-IMPLEMENTATION-STATUS.md    # Pure CLI implementation status
├── capability-developer-completion.md   # Final completion report
└── Various session summaries
```

---

## Verification Commands

```bash
# Verify ZERO Tabularium imports in production code
cd modules/diocletian
grep -r "tabularium" pkg --include="*.go" | grep -v "_test.go"
# Expected: empty output

# Verify build
go build ./...

# Verify tests
go test ./...
```

---

## Metrics

| Metric | Value |
|--------|-------|
| Files migrated | ~57 |
| Lines of new code | ~640 (types + relationships + outputter) |
| Lines removed | ~200 (Tabularium imports/wrappers) |
| Agent sessions | 13 |
| Architecture revisions | 1 (Hybrid → Pure CLI) |
