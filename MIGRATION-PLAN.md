# Janus Framework Complete Removal Migration Plan

**Date:** 2026-02-04
**Author:** backend-lead (Claude)
**Scope:** Complete unbinding of Janus framework from Aurelian

---

## Executive Summary

This plan outlines the complete removal of the `github.com/praetorian-inc/janus-framework` dependency from Aurelian. The migration follows a phased approach, prioritizing dependencies to minimize risk and enable incremental verification.

### Current State (2026-02-04)

| Component | Files with Janus | Status |
|-----------|------------------|--------|
| `pkg/links/` | 115 files (253 occurrences) | NOT MIGRATED |
| `pkg/outputters/` | 14 files (29 occurrences) | NOT MIGRATED |
| `pkg/iam/aws/` | 5 files (7 occurrences) | NOT MIGRATED |
| `internal/registry/` | 1 file | DEPRECATED (delete) |
| `cmd/root.go` | 1 file | Log level only |
| `cmd/output_selector.go` | 1 file | Uses chain package |
| `pkg/types/` | 2 files | Uses jtypes |
| `pkg/modules/` (incomplete) | 5 modules | Return errors |

### Target Architecture

The existing `pkg/plugin/` package provides the native replacement:

- `pkg/plugin/module.go` - Module interface (replaces `chain.Module`)
- `pkg/plugin/registry.go` - Thread-safe registry (replaces `internal/registry/`)
- `pkg/plugin/processor.go` - Pipeline pattern (replaces `chain.Link` composition)
- `pkg/plugin/output.go` - Formatter interface (replaces `chain.Outputter`)

---

## Phase 0: Foundation Cleanup (Estimated: 30 minutes)

**Goal:** Remove dead code and prepare for migration.

### Files to Delete

| File | Reason |
|------|--------|
| `internal/registry/registry.go` | Deprecated - uses old `chain.Module` type |
| `pkg/links/aws/whoami.go` | Duplicate - native version exists in `pkg/modules/aws/recon/whoami.go` |

### Files to Verify

```bash
# Verify internal/registry is unused (should return 0 matches in pkg/modules)
grep -r "internal/registry" /Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/
```

### Exit Criteria

- [ ] `internal/registry/` directory deleted
- [ ] No import of `internal/registry` in any file (verify: `grep -r "aurelian/internal/registry" . | wc -l` returns 0)
- [ ] `go build ./...` succeeds

---

## Phase 1: Define Native Types (Estimated: 1 hour)

**Goal:** Create native replacements for Janus types used across the codebase.

### 1.1 Create Native NPInput Type

**Location:** `pkg/types/nosey_parker.go` (already exists, extend)

The Janus `jtypes.NPInput` and `jtypes.NPProvenance` types are used in several modules. Create native equivalents.

**Pattern:**

```go
// pkg/types/nosey_parker.go
package types

// NPInput represents content to scan with NoseyParker
// This replaces github.com/praetorian-inc/janus-framework/pkg/types.NPInput
type NPInput struct {
    Content    string       `json:"content"`
    Provenance NPProvenance `json:"provenance"`
}

// NPProvenance tracks the origin of scanned content
type NPProvenance struct {
    Platform     string `json:"platform"`
    ResourceType string `json:"resource_type"`
    ResourceID   string `json:"resource_id"`
    AccountID    string `json:"account_id"`
    FilePath     string `json:"file_path,omitempty"`
}
```

### 1.2 Create Native cfg.Param Replacement

**Location:** `pkg/plugin/params.go` (new file)

The Janus `cfg.Param` and `cfg.Config` types are used extensively in `pkg/links/options/`. Create a shim that provides the same API.

**Pattern:**

```go
// pkg/plugin/params.go
package plugin

// Param defines a module parameter (replaces cfg.Param)
// This is already defined in module.go as Parameter - unify the naming

// ParamOption allows building parameters fluently
type ParamOption func(*Parameter)

// NewParam creates a new parameter (mirrors cfg.NewParam API)
func NewParam[T any](name, description string, opts ...ParamOption) Parameter {
    p := Parameter{
        Name:        name,
        Description: description,
        Type:        detectType[T](),
    }
    for _, opt := range opts {
        opt(&p)
    }
    return p
}

func WithDefault[T any](val T) ParamOption {
    return func(p *Parameter) {
        p.Default = val
    }
}

func WithRequired() ParamOption {
    return func(p *Parameter) {
        p.Required = true
    }
}

func WithShortcode(s string) ParamOption {
    return func(p *Parameter) {
        p.Shortcode = s
    }
}

func detectType[T any]() string {
    var zero T
    switch any(zero).(type) {
    case string:
        return "string"
    case int:
        return "int"
    case bool:
        return "bool"
    case []string:
        return "[]string"
    default:
        return "any"
    }
}
```

### 1.3 Migrate Options Helpers

**Files to Modify:** `pkg/links/options/*.go` (8 files)

These files define parameter helpers using Janus `cfg.Param`. Migrate to use native `plugin.Parameter`.

**Before:**

```go
import "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"

func AwsProfile() cfg.Param {
    return cfg.NewParam[string]("profile", "AWS profile").WithDefault("")
}
```

**After:**

```go
import "github.com/praetorian-inc/aurelian/pkg/plugin"

func AwsProfile() plugin.Parameter {
    return plugin.NewParam[string]("profile", "AWS profile", plugin.WithDefault(""))
}
```

### Exit Criteria

- [ ] `pkg/types/nosey_parker.go` contains native NPInput and NPProvenance
- [ ] `pkg/plugin/params.go` provides NewParam builder API
- [ ] All 8 files in `pkg/links/options/` no longer import `janus-framework/pkg/chain/cfg`
- [ ] `go build ./...` succeeds
- [ ] `grep -r "janus-framework" pkg/links/options/ | wc -l` returns 0

---

## Phase 2: Migrate pkg/outputters (Estimated: 2 hours)

**Goal:** Replace Janus outputters with native formatters.

### Strategy

The `pkg/plugin/output.go` already defines the native `Formatter` interface. The outputters need to implement this interface instead of `chain.Outputter`.

### 2.1 Create Outputter Adapter

**Location:** `pkg/plugin/outputter.go` (new file)

Create an adapter that allows existing outputter logic to work with the new system:

```go
// pkg/plugin/outputter.go
package plugin

import (
    "io"
)

// Outputter is the native interface for output handling
// This replaces chain.Outputter
type Outputter interface {
    // Initialize prepares the outputter (called before first output)
    Initialize() error

    // Output writes a single result
    Output(result any) error

    // Complete finalizes output (called after all outputs)
    Complete() error
}

// OutputterFunc adapts a function to the Outputter interface
type OutputterFunc func(any) error

func (f OutputterFunc) Initialize() error { return nil }
func (f OutputterFunc) Output(v any) error { return f(v) }
func (f OutputterFunc) Complete() error { return nil }
```

### 2.2 Migrate Each Outputter

**Files to Modify (14 total):**

| File | Priority | Notes |
|------|----------|-------|
| `formatter_adapter.go` | HIGH | Bridge to capability-sdk, remove chain.BaseOutputter |
| `runtime_json.go` | HIGH | Most commonly used |
| `raw_output.go` | HIGH | Simple passthrough |
| `erd_console.go` | MEDIUM | EnrichedResourceDescription console output |
| `risk_console_outputter.go` | MEDIUM | Risk console output |
| `markdown_table_console.go` | MEDIUM | Table formatting |
| `runtime_markdown.go` | MEDIUM | Markdown output |
| `np_findings_console.go` | MEDIUM | NoseyParker findings |
| `url_console.go` | LOW | URL output |
| `screenshot_outputter.go` | LOW | Screenshot display |
| `azure_resource_outputter.go` | LOW | Azure-specific |
| `arg_scan_output.go` | LOW | ARG scan output |
| `neo4j_graph_outputter.go` | LOW | Neo4j integration |
| `risk_csv_outputter.go` | LOW | CSV export |
| `base_file.go` | LOW | File output base |

**Migration Pattern:**

**Before (Janus):**

```go
import (
    "github.com/praetorian-inc/janus-framework/pkg/chain"
    "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

type RuntimeJSONOutputter struct {
    *chain.BaseOutputter
    writer io.Writer
}

func NewRuntimeJSONOutputter(configs ...cfg.Config) chain.Outputter {
    o := &RuntimeJSONOutputter{}
    o.BaseOutputter = chain.NewBaseOutputter(o)
    return o
}

func (o *RuntimeJSONOutputter) Output(val any) error { ... }
func (o *RuntimeJSONOutputter) Params() []cfg.Param { return nil }
```

**After (Native):**

```go
import (
    "github.com/praetorian-inc/aurelian/pkg/plugin"
)

type RuntimeJSONOutputter struct {
    writer io.Writer
    results []any
}

func NewRuntimeJSONOutputter(w io.Writer) *RuntimeJSONOutputter {
    if w == nil {
        w = os.Stdout
    }
    return &RuntimeJSONOutputter{writer: w}
}

func (o *RuntimeJSONOutputter) Initialize() error { return nil }

func (o *RuntimeJSONOutputter) Output(val any) error {
    o.results = append(o.results, val)
    return nil
}

func (o *RuntimeJSONOutputter) Complete() error {
    encoder := json.NewEncoder(o.writer)
    encoder.SetIndent("", "  ")
    return encoder.Encode(o.results)
}
```

### Exit Criteria

- [ ] All 14 files in `pkg/outputters/` no longer import `janus-framework`
- [ ] Each outputter implements native `Outputter` interface
- [ ] Unit tests for outputters pass (`go test ./pkg/outputters/...`)
- [ ] `grep -r "janus-framework" pkg/outputters/ | wc -l` returns 0

---

## Phase 3: Migrate pkg/links Base Classes (Estimated: 3 hours)

**Goal:** Create native base classes to replace Janus chain.Base.

### 3.1 Create Native Link Base

**Location:** `pkg/plugin/link.go` (new file)

```go
// pkg/plugin/link.go
package plugin

import (
    "context"
    "log/slog"
)

// Link represents a processing unit in a pipeline
// This replaces chain.Link
type Link interface {
    // Process handles a single input and may produce outputs
    Process(ctx context.Context, input any) ([]any, error)

    // Parameters returns the link's parameter definitions
    Parameters() []Parameter
}

// BaseLink provides common functionality for links
// This replaces chain.Base
type BaseLink struct {
    name    string
    args    map[string]any
    outputs []any
    logger  *slog.Logger
}

func NewBaseLink(name string, args map[string]any) *BaseLink {
    return &BaseLink{
        name:   name,
        args:   args,
        logger: slog.Default().With("link", name),
    }
}

// Arg retrieves a typed argument value
func (b *BaseLink) Arg(name string) any {
    return b.args[name]
}

// ArgString retrieves a string argument with default
func (b *BaseLink) ArgString(name string, defaultVal string) string {
    if v, ok := b.args[name].(string); ok {
        return v
    }
    return defaultVal
}

// ArgBool retrieves a bool argument with default
func (b *BaseLink) ArgBool(name string, defaultVal bool) bool {
    if v, ok := b.args[name].(bool); ok {
        return v
    }
    return defaultVal
}

// ArgInt retrieves an int argument with default
func (b *BaseLink) ArgInt(name string, defaultVal int) int {
    if v, ok := b.args[name].(int); ok {
        return v
    }
    return defaultVal
}

// ArgStringSlice retrieves a []string argument with default
func (b *BaseLink) ArgStringSlice(name string, defaultVal []string) []string {
    if v, ok := b.args[name].([]string); ok {
        return v
    }
    return defaultVal
}

// Send adds output to the collection (replaces l.Send())
func (b *BaseLink) Send(val any) {
    b.outputs = append(b.outputs, val)
}

// Outputs returns all collected outputs
func (b *BaseLink) Outputs() []any {
    return b.outputs
}

// Logger returns the link's logger
func (b *BaseLink) Logger() *slog.Logger {
    return b.logger
}
```

### 3.2 Create Platform-Specific Base Links

**Files to Create:**

| File | Purpose |
|------|---------|
| `pkg/links/aws/base/native_base.go` | AWS-specific base link |
| `pkg/links/gcp/base/native_base.go` | GCP-specific base link |
| `pkg/links/azure/base/native_base.go` | Azure-specific base link |

**Pattern for AWS:**

```go
// pkg/links/aws/base/native_base.go
package base

import (
    "context"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/praetorian-inc/aurelian/internal/helpers"
    "github.com/praetorian-inc/aurelian/pkg/plugin"
    "github.com/praetorian-inc/aurelian/pkg/types"
)

// NativeAWSLink is the base for all AWS links (replaces AwsReconBaseLink)
type NativeAWSLink struct {
    *plugin.BaseLink
    Profile    string
    ProfileDir string
    Regions    []string
}

func NewNativeAWSLink(name string, args map[string]any) *NativeAWSLink {
    base := plugin.NewBaseLink(name, args)
    return &NativeAWSLink{
        BaseLink:   base,
        Profile:    base.ArgString("profile", ""),
        ProfileDir: base.ArgString("profile-dir", ""),
    }
}

// GetConfig returns AWS SDK config for the specified region
func (l *NativeAWSLink) GetConfig(ctx context.Context, region string) (aws.Config, error) {
    var opts []*types.Option
    if l.ProfileDir != "" {
        opts = append(opts, &types.Option{Name: "profile-dir", Value: l.ProfileDir})
    }
    return helpers.GetAWSCfg(region, l.Profile, opts, "")
}

// StandardAWSParams returns common AWS parameters
func StandardAWSParams() []plugin.Parameter {
    return []plugin.Parameter{
        {Name: "profile", Description: "AWS profile name", Type: "string"},
        {Name: "profile-dir", Description: "AWS profile directory", Type: "string"},
        {Name: "regions", Description: "AWS regions to query", Type: "[]string", Default: []string{"all"}},
    }
}
```

### Exit Criteria

- [ ] `pkg/plugin/link.go` created with BaseLink struct
- [ ] Platform-specific native base links created (AWS, GCP, Azure)
- [ ] `go build ./pkg/plugin/...` succeeds
- [ ] `go build ./pkg/links/aws/base/...` succeeds
- [ ] `go build ./pkg/links/gcp/base/...` succeeds

---

## Phase 4: Migrate pkg/links (Estimated: 8 hours)

**Goal:** Migrate all 115 link files to use native base classes.

### Strategy: Incremental by Platform

Migrate links in this order (least to most complex):

1. `pkg/links/general/` (5 files) - Simple utilities
2. `pkg/links/options/` (8 files) - Already done in Phase 1
3. `pkg/links/gcp/` (11 files) - Moderate complexity
4. `pkg/links/docker/` (7 files) - Moderate complexity
5. `pkg/links/azure/` (38 files) - Higher complexity
6. `pkg/links/aws/` (46 files) - Highest complexity
7. `pkg/links/llm/` (2 files) - LLM integration

### 4.1 Migrate General Links

**Files (5):**

| File | Complexity |
|------|------------|
| `echo.go` | LOW - Simple passthrough |
| `jq.go` | LOW - JQ filtering |
| `unmarshal.go` | LOW - JSON unmarshal |
| `generator.go` | MEDIUM - Generates items |
| `preprocess_resources.go` | MEDIUM - Resource preprocessing |

**Migration Pattern (echo.go):**

**Before:**

```go
import (
    "github.com/praetorian-inc/janus-framework/pkg/chain"
    "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

type Echo[T any] struct {
    *chain.Base
}

func NewEcho[T any](configs ...cfg.Config) chain.Link {
    e := &Echo[T]{}
    e.Base = chain.NewBase(e, configs...)
    return e
}

func (e *Echo[T]) Process(input T) error {
    e.Send(input)
    return nil
}
```

**After:**

```go
import (
    "context"

    "github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Echo passes input through unchanged
type Echo struct {
    *plugin.BaseLink
}

func NewEcho(args map[string]any) *Echo {
    return &Echo{
        BaseLink: plugin.NewBaseLink("echo", args),
    }
}

func (e *Echo) Process(ctx context.Context, input any) ([]any, error) {
    return []any{input}, nil
}

func (e *Echo) Parameters() []plugin.Parameter {
    return nil
}
```

### 4.2 Migrate GCP Links (11 files)

| Directory | Files |
|-----------|-------|
| `gcp/base/` | 1 file |
| `gcp/hierarchy/` | 3 files (projects, folders, organization) |
| `gcp/storage/` | 2 files (bucket, sql) |
| `gcp/compute/` | 2 files (instances, networking) |
| `gcp/applications/` | 3 files (app_engine, cloud_run, functions_legacy) |
| `gcp/containers/` | 1 file (artifactory) |

### 4.3 Migrate Docker Links (7 files)

| File | Purpose |
|------|---------|
| `pull.go` | Pull Docker image |
| `save.go` | Save Docker image |
| `extract.go` | Extract image layers |
| `aggregator.go` | Aggregate scan results |
| `scan_summary.go` | Scan summary |
| `helpers.go` | Utility functions |

### 4.4 Migrate Azure Links (38 files)

**Subgroups:**

| Group | Files | Purpose |
|-------|-------|---------|
| DevOps | 8 | Azure DevOps integration |
| Secrets | 6 | Secret scanning |
| Conditional Access | 7 | CA policy analysis |
| ARG | 3 | Azure Resource Graph |
| Enrichers | 14 | Resource enrichment |

### 4.5 Migrate AWS Links (46 files)

**Subgroups:**

| Group | Files | Purpose |
|-------|-------|---------|
| Base | 3 | Base classes |
| EC2 | 2 | EC2 operations |
| ECR | 4 | Container registry |
| CloudFront | 3 | CDN operations |
| Lambda | 2 | Serverless |
| CloudControl | 2 | Resource enumeration |
| StepFunctions | 2 | Workflow |
| SSM | 1 | Parameter store |
| CloudWatch | 1 | Logs |
| Cognito | 1 | Identity |
| CloudFormation | 1 | IaC |
| OrgPolicies | 1 | Organizations |
| Apollo | 4 | Apollo integration |
| CDK | 5 | CDK operations |
| Core | ~14 | Core operations |

### Exit Criteria

- [ ] All 115 files in `pkg/links/` no longer import `janus-framework`
- [ ] Each link implements native `Link` interface
- [ ] `go build ./pkg/links/...` succeeds
- [ ] `grep -r "janus-framework" pkg/links/ | wc -l` returns 0

---

## Phase 5: Migrate pkg/iam/aws Links (Estimated: 1 hour)

**Goal:** Migrate IAM-specific links that use Janus.

**Files (5):**

| File | Purpose |
|------|---------|
| `action.go` | IAM action parsing |
| `action_classifier_link.go` | Action classification |
| `expand_iam_actions_link.go` | Action expansion |
| `action_classifier_link_test.go` | Tests |
| `expand_iam_actions_link_test.go` | Tests |

**Strategy:**

These links perform IAM policy analysis. Migrate using the same pattern as Phase 4 links.

### Exit Criteria

- [ ] All 5 files in `pkg/iam/aws/` no longer import `janus-framework`
- [ ] `go test ./pkg/iam/aws/...` passes
- [ ] `grep -r "janus-framework" pkg/iam/aws/ | wc -l` returns 0

---

## Phase 6: Complete Incomplete Modules (Estimated: 2 hours)

**Goal:** Implement the 5 modules that currently return "not implemented" errors.

### Modules to Complete

| Module | File | Current Status |
|--------|------|----------------|
| AWS find-secrets | `pkg/modules/aws/recon/find_secrets.go` | Returns error |
| AWS find-secrets-resource | `pkg/modules/aws/recon/find_secrets_resource.go` | Returns error |
| Azure arg-scan | `pkg/modules/azure/recon/arg_scan.go` | Returns error |
| GCP scan-storage | `pkg/modules/gcp/secrets/scan_storage.go` | Returns error |
| SaaS docker-dump | `pkg/modules/saas/recon/docker_dump.go` | Returns error |

### Implementation Pattern

Each incomplete module currently has a stub like:

```go
func (m *FindSecrets) Run(cfg plugin.Config) ([]plugin.Result, error) {
    // ... parameter extraction ...
    return nil, fmt.Errorf("module implementation pending: find-secrets needs to be migrated...")
}
```

**Strategy:**

1. Use the corresponding link files as reference implementation
2. Inline the link logic directly into the module's `Run()` method
3. Replace `l.Send()` with collecting results into `[]plugin.Result`
4. Replace `l.Arg()` with reading from `cfg.Args`

### Exit Criteria

- [ ] All 5 modules return actual results (not errors)
- [ ] Manual testing: `aurelian aws recon find-secrets --help` works
- [ ] Manual testing: `aurelian azure recon arg-scan --help` works
- [ ] `grep -r "implementation pending" pkg/modules/ | wc -l` returns 0

---

## Phase 7: Remove pkg/types Janus Dependencies (Estimated: 30 minutes)

**Goal:** Remove remaining Janus type imports from pkg/types.

### Files to Modify

| File | Current Janus Usage |
|------|---------------------|
| `pkg/types/output_providers.go` | Likely imports jtypes |
| `pkg/types/enriched_resource_description.go` | Uses jtypes.ERD |

### Strategy

Replace Janus types with native equivalents defined in Phase 1.

### Exit Criteria

- [ ] `grep -r "janus-framework" pkg/types/ | wc -l` returns 0
- [ ] `go build ./pkg/types/...` succeeds

---

## Phase 8: Clean Up cmd/ (Estimated: 30 minutes)

**Goal:** Remove final Janus references from CLI code.

### Files to Modify

| File | Current Janus Usage | Action |
|------|---------------------|--------|
| `cmd/root.go` | `cfg.LevelFromString` | Replace with stdlib slog levels |
| `cmd/output_selector.go` | Uses chain package | Replace with native outputter selection |

### Exit Criteria

- [ ] `grep -r "janus-framework" cmd/ | wc -l` returns 0
- [ ] `go build ./cmd/...` succeeds

---

## Phase 9: Remove Janus Dependency (Estimated: 15 minutes)

**Goal:** Remove Janus framework from go.mod.

### Steps

1. Run final verification:
   ```bash
   grep -r "janus-framework" /Users/nathansportsman/capabilities/modules/aurelian/ --include="*.go" | wc -l
   # Must return 0
   ```

2. Remove from go.mod:
   ```bash
   go mod edit -droprequire github.com/praetorian-inc/janus-framework
   ```

3. Clean up go.sum:
   ```bash
   go mod tidy
   ```

4. Verify build:
   ```bash
   go build ./...
   ```

5. Run tests:
   ```bash
   go test ./...
   ```

### Exit Criteria

- [ ] `janus-framework` not in go.mod
- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes (all tests)
- [ ] `grep -r "janus-framework" . --include="*.go" | wc -l` returns 0

---

## Phase 10: Update Documentation (Estimated: 30 minutes)

**Goal:** Update all documentation to reflect native architecture.

### Files to Update

| File | Required Changes |
|------|------------------|
| `README.md` | Remove Janus references, document native plugin system |
| `DEVELOPMENT.md` | Update development patterns for native architecture |
| `ARCHITECTURE-REVIEW.md` | Update status to COMPLETE |
| `aurelian-janus-bounded.md` | Archive or delete |

### Exit Criteria

- [ ] `README.md` documents `pkg/plugin/` architecture
- [ ] No mention of Janus as current architecture
- [ ] `aurelian-janus-bounded.md` deleted or moved to archive

---

## Summary

### Total Estimated Time: 19 hours

| Phase | Description | Estimated Time |
|-------|-------------|----------------|
| 0 | Foundation Cleanup | 30 min |
| 1 | Define Native Types | 1 hour |
| 2 | Migrate pkg/outputters | 2 hours |
| 3 | Migrate Link Base Classes | 3 hours |
| 4 | Migrate pkg/links | 8 hours |
| 5 | Migrate pkg/iam/aws | 1 hour |
| 6 | Complete Incomplete Modules | 2 hours |
| 7 | Remove pkg/types Dependencies | 30 min |
| 8 | Clean Up cmd/ | 30 min |
| 9 | Remove Janus Dependency | 15 min |
| 10 | Update Documentation | 30 min |

### Risk Assessment

| Risk | Mitigation |
|------|------------|
| Breaking existing functionality | Incremental migration with phase-by-phase verification |
| Test coverage gaps | Run `go test ./...` after each phase |
| Missing edge cases in links | Keep original link files as reference until migration complete |
| Performance regression | Compare output of migrated vs original modules |

### Success Metrics

1. **Zero Janus imports:** `grep -r "janus-framework" . --include="*.go" | wc -l` returns 0
2. **All tests pass:** `go test ./...` exits with 0
3. **All modules functional:** No "implementation pending" errors
4. **Build succeeds:** `go build ./...` exits with 0
5. **go.mod clean:** Janus framework not listed as dependency

---

## Section for Capability-Lead Agent

**Please add capability-specific migration considerations here:**

- VQL integration patterns that may need updating
- Template YAML migration considerations
- NoseyParker integration approach
- Any scanner-specific dependencies on Janus

---

## Metadata

```json
{
  "agent": "backend-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-02-04T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/aurelian",
  "skills_invoked": [
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "structuring-go-projects",
    "behavior-first-architecture-analysis",
    "adhering-to-dry",
    "adhering-to-yagni",
    "writing-plans",
    "verifying-before-completion"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/module.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/registry.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/output.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/plugin/processor.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/internal/registry/registry.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/links/aws/base/aws_recon_link.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/links/general/echo.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/outputters/formatter_adapter.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/cmd/generator.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/cmd/module_imports.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/aws/recon/whoami.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/aws/recon/find_secrets.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/pkg/modules/gcp/secrets/scan_functions.go",
    "/Users/nathansportsman/capabilities/modules/aurelian/go.mod"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Implement Janus unbinding migration following this phased plan"
  }
}
```
