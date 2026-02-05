# Azure Links Migration Analysis
## Deep Dive: pkg/links/azure/ Janus Unbinding

**Date**: 2026-02-04
**Analyst**: capability-developer
**Scope**: 47 Go files in pkg/links/azure/

---

## Executive Summary

The Azure links migration is **more complex than initially assessed**. The architecture uses **two patterns**:

1. **Module Pattern**: Standalone executables (implement `plugin.Module`)
2. **Link Pattern**: Chain processing units (implement `plugin.Link` via `*base.NativeAzureLink`)

**Current Status**: 61 janus-framework imports remain across 47 files.

**Blocker Identified**: Architectural decision needed on whether Azure links should be:
- **Modules** (standalone CLI commands) → Implement full Module interface
- **Links** (chain processors) → Use BaseLink pattern but need integration with pipeline

---

## Architecture Patterns

### Pattern 1: Module (AWS Example)

**File**: `pkg/links/aws/access_key_to_account_id.go`

```go
type AccessKeyToAccountID struct{}

func init() {
	plugin.Register(&AccessKeyToAccountID{})
}

func (m *AccessKeyToAccountID) ID() string { return "access-key-to-account-id" }
func (m *AccessKeyToAccountID) Name() string { return "..." }
func (m *AccessKeyToAccountID) Description() string { return "..." }
func (m *AccessKeyToAccountID) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AccessKeyToAccountID) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AccessKeyToAccountID) OpsecLevel() string { return "low" }
func (m *AccessKeyToAccountID) Authors() []string { return []string{"Praetorian"} }
func (m *AccessKeyToAccountID) References() []string { return []string{} }
func (m *AccessKeyToAccountID) Parameters() []plugin.Parameter { return []plugin.Parameter{...} }
func (m *AccessKeyToAccountID) Run(cfg plugin.Config) ([]plugin.Result, error) { ... }
```

**Characteristics**:
- ✅ Standalone CLI command
- ✅ No base embedding
- ✅ Implements full Module interface (11 methods)
- ✅ Registered via `plugin.Register()`

### Pattern 2: Link (AWS Base Example)

**File**: `pkg/links/aws/base/native_base.go`

```go
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
		Regions:    base.ArgStringSlice("regions", []string{"all"}),
	}
}
```

**Characteristics**:
- ✅ Chain processing unit
- ✅ Embeds `*plugin.BaseLink`
- ✅ Implements `plugin.Link` interface
- ❓ **How is it registered/invoked in pipelines?**

---

## Azure Links Current State

### Example: automation_secrets.go

**Current (Janus)**:
```go
type AzureAutomationSecretsLink struct {
	*chain.Base
}

func NewAzureAutomationSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureAutomationSecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureAutomationSecretsLink) Process(resource *output.CloudResource) error {
	// ... scan automation secrets
	l.Send(npInput)  // ← Sends to chain
	return nil
}
```

**Target (Native - Link Pattern)**:
```go
type AzureAutomationSecretsLink struct {
	*base.NativeAzureLink
}

func NewAzureAutomationSecretsLink(args map[string]any) *AzureAutomationSecretsLink {
	return &AzureAutomationSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-automation-secrets", args),
	}
}

func (l *AzureAutomationSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	// ... scan automation secrets
	return results, nil  // ← Returns results
}
```

**Target (Native - Module Pattern)**:
```go
type AzureAutomationSecretsModule struct{}

func init() {
	plugin.Register(&AzureAutomationSecretsModule{})
}

func (m *AzureAutomationSecretsModule) ID() string { ... }
// ... 10 more Module interface methods ...

func (m *AzureAutomationSecretsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// ... scan automation secrets
	return results, nil
}
```

---

## Critical Questions Needing Architecture Decision

### Q1: Module vs Link?

**Azure links currently use chain.Link pattern** (Process method, Send outputs to chain).

**Options**:

**Option A: Convert to Modules** (like AWS access_key_to_account_id.go)
- ✅ Standalone executables
- ✅ Clear registration via `plugin.Register()`
- ❌ Loses chain processing capability
- ❌ Each file needs 11 Module interface methods

**Option B: Keep as Links** (like AWS native_base.go pattern)
- ✅ Maintains chain processing
- ✅ Simpler interface (just Process method)
- ❓ **How are links discovered/registered?**
- ❓ **How are links invoked in pipelines?**

**Recommendation**: Need to examine how `pkg/links/aws` links are actually used:
- Are they imported and used programmatically?
- Or are they CLI commands?
- What invokes `Process(ctx, input)`?

### Q2: What type should Process() accept?

Current: `Process(resource *output.CloudResource) error`
Target: `Process(ctx context.Context, input any) ([]any, error)`

**But**: Most Azure links are **resource-specific** (automation accounts, key vaults, storage).

**Options**:

**Option A: Type assertion in each link**
```go
func (l *Link) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}
	// ... process resource
}
```

**Option B: Typed base links**
```go
type ResourceLink[T any] struct {
	*plugin.BaseLink
}

func (l *ResourceLink[T]) Process(ctx context.Context, input any) ([]any, error) {
	typed, ok := input.(T)
	if !ok {
		return nil, fmt.Errorf("expected %T, got %T", *new(T), input)
	}
	return l.ProcessTyped(ctx, typed)
}
```

**Recommendation**: Option A is simpler; Option B is more type-safe but requires Go 1.18+ generics.

### Q3: How to handle jtypes.NPInput?

Current: Azure links create `jtypes.NPInput` structs with provenance metadata.
Target: Return `[]any` or `[]plugin.Result`

**NPInput structure**:
```go
// janus-framework type (to remove)
type NPInput struct {
	Content    string
	Provenance NPProvenance
}
```

**Migration options**:

**Option A: Return raw maps** (loses type safety)
```go
return []any{
	map[string]any{
		"content": metadataJSON,
		"provenance": map[string]any{
			"platform": "azure",
			"resource_id": resourceID,
		},
	},
}, nil
```

**Option B: Define native NP types** (preserves structure)
```go
// Create pkg/types/noseyparker.go
type NPInput struct {
	Content    string
	Provenance NPProvenance
}

// Return typed results
return []any{npInput}, nil
```

**Option C: Use plugin.Result metadata**
```go
return []plugin.Result{
	{
		Data: metadataJSON,
		Metadata: map[string]any{
			"provenance": map[string]any{...},
		},
	},
}, nil
```

**Recommendation**: Option B (define native types) maintains structure while removing Janus dependency.

---

## Proposed Migration Strategy (Revised)

### Phase 0: Architecture Clarification (BLOCKE R)

**Before migrating 47 files**, resolve:

1. **Examine AWS link usage**:
   ```bash
   grep -r "NewNative" modules/aurelian/ --include="*.go" -B 2 -A 5
   ```
   Find examples of how NativeAWSLink is actually instantiated.

2. **Find link invocation**:
   ```bash
   grep -r "\.Process(" pkg/ --include="*.go" | grep -v "// "
   ```
   Understand who calls `Process()` and how links are discovered.

3. **Decision Matrix**:
   | If links are... | Then migrate to... | Example |
   |---|---|---|
   | CLI commands | Module pattern | access_key_to_account_id.go |
   | Pipeline processors | Link pattern | NativeAWSLink |
   | Mixed usage | Hybrid (both patterns) | TBD |

### Phase 1: Pilot Migration (1 file)

**Select**: `automation_secrets.go` (representative complexity)

**Steps**:
1. Implement chosen pattern (Module or Link)
2. Verify compilation
3. Test invocation (how is it called?)
4. Document any gaps

### Phase 2: Pattern Refinement

**Based on pilot results**:
- Update `AZURE_LINKS_MIGRATION_PLAN.md` with verified pattern
- Create helper scripts/templates
- Document gotchas

### Phase 3: Batch Migration

**Groups** (as defined in migration plan):
- Core links (15 files)
- DevOps links (7 files)
- Conditional access (7 files)
- Enrichers (15 files)

**Per group**:
1. Migrate all files
2. Test compilation: `go build ./pkg/links/azure/`
3. Integration test: `go test ./pkg/links/azure/...`

### Phase 4: Verification

**Final checks**:
```bash
# Must all pass:
grep -r "janus-framework" pkg/links/azure/ | wc -l  # = 0
grep -r "chain\.Base" pkg/links/azure/ | wc -l      # = 0
go build ./...                                       # success
go test ./pkg/links/azure/...                        # pass
```

---

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| **Wrong pattern chosen** | High - rework all 47 files | Medium | Phase 0 investigation |
| **Type conversion breaks semantics** | High - runtime errors | Medium | Pilot migration testing |
| **NoseyParker integration breaks** | Medium - secret scanning fails | Low | Option B (native types) |
| **Test coverage insufficient** | Medium - bugs in production | High | Phase 2 test strategy |
| **Context threading complex** | Low - compile errors | High | Mechanical change |

---

## Estimated Effort (Revised)

**Phase 0 (Architecture Clarification)**: 4-8 hours
- Investigate AWS link usage
- Document patterns
- Make architecture decision

**Phase 1 (Pilot)**: 4-6 hours
- Migrate automation_secrets.go
- Test end-to-end
- Document process

**Phase 2 (Pattern Refinement)**: 2-4 hours
- Update documentation
- Create templates

**Phase 3 (Batch Migration)**: 30-45 hours
- 47 files × 30-60 min each
- Grouped testing
- Bug fixes

**Phase 4 (Verification)**: 4-8 hours
- Integration testing
- Documentation updates

**Total**: 44-71 hours (confirms lead's 40-60 hour estimate)

---

## Recommendations

1. **BLOCK on Phase 0**: Do NOT migrate remaining files until architecture is clarified.

2. **Create decision document**: Propose Module vs Link pattern with evidence from AWS usage.

3. **Get lead approval**: Present options and get architectural decision before proceeding.

4. **Pilot with 1 file**: Validate chosen pattern works end-to-end.

5. **Automate where possible**: Create migration scripts after pattern is verified.

---

## Files for Phase 0 Investigation

**Must examine**:
- How `pkg/links/aws/base/native_base.go` is used
- Where `NativeAWSLink.Process()` is called
- How links are discovered/registered
- Example pipeline that uses links

**Commands to run**:
```bash
# Find link instantiation
find . -name "*.go" -exec grep -l "NewNativeAWSLink\|NewNativeAzureLink" {} \;

# Find Process() calls
grep -r "\.Process(ctx" . --include="*.go" | grep -v "// " | head -20

# Find link registration
grep -r "RegisterLink\|linkRegistry" . --include="*.go"

# Find pipeline/chain usage
grep -r "pipeline\|chain\|workflow" . --include="*.go" -i | grep -v vendor | head -20
```

---

## Status

🛑 **BLOCKED**: Architecture pattern must be clarified before continuing migration.

**Next Action**: Investigate Phase 0 questions and present findings to lead for decision.
