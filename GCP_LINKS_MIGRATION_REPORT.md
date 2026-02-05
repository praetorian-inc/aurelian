# GCP Links Migration - Progress Report
**Date**: 2026-02-04  
**Task**: Phase 5 of Aurelian Janus Unbinding - Migrate pkg/links/gcp/  
**Status**: IN PROGRESS (7.7% complete)

---

## Executive Summary

Successfully established migration pattern by completing `organization.go`. Remaining 12 files follow identical pattern - mechanical transformation with low risk.

## Progress

### ✅ Completed (1/13 files)
- `pkg/links/gcp/hierarchy/organization.go` - **MIGRATED**
  - 4 link types migrated: GcpOrganizationLister, GcpOrgInfoLink, GcpOrgFolderListLink, GcpOrgProjectListLink
  - Janus imports eliminated: 2 imports removed
  - Pattern validated: compiles, no errors
  - Backup saved: organization.go.bak

### 📊 Verification Metrics
- **Janus imports remaining**: 28 (down from 30)
- **Files remaining**: 12 (11 to migrate + 1 to delete)
- **Completion**: 7.7%

### 📋 Remaining Work (12 files)

#### To Migrate (11 files)
1. `pkg/links/gcp/base/gcp_base_link.go` - **DELETE** (replaced by native_base.go)
2. `pkg/links/gcp/hierarchy/folders.go` - 3 link types
3. `pkg/links/gcp/hierarchy/projects.go` - 3 link types
4. `pkg/links/gcp/storage/bucket.go` - 2 link types
5. `pkg/links/gcp/storage/sql.go` - 1 link type
6. `pkg/links/gcp/compute/instances.go` - 1 link type
7. `pkg/links/gcp/compute/networking.go` - 2 link types
8. `pkg/links/gcp/applications/app_engine.go` - 1 link type
9. `pkg/links/gcp/applications/cloud_run.go` - 1 link type
10. `pkg/links/gcp/applications/functions_legacy.go` - 1 link type
11. `pkg/links/gcp/containers/artifactory.go` - 1 link type

---

## Migration Pattern (ESTABLISHED)

### Key Transformations

| Aspect | Before (Janus) | After (Native) |
|--------|---------------|----------------|
| Base type | `*base.GcpBaseLink` | `*base.NativeGCPLink` |
| Constructor | `NewXxx(configs ...cfg.Config) chain.Link` | `NewXxx(args map[string]any) *Xxx` |
| Process | `Process(input T) error` | `Process(ctx context.Context, input any) ([]any, error)` |
| Initialize | Has Initialize() method | **DELETED** - services created in Process |
| Parameters | `Params() []cfg.Param` | `Parameters() []plugin.Parameter` |
| Output | `g.Send(output)` | `results = append(results, output)` + `return results, nil` |
| Context | `context.Background()` | `ctx` (from Process parameter) |
| Client opts | `g.ClientOptions...` | `g.ClientOptions()...` |

### Example: GcpOrganizationLister

**Before (Janus):**
```go
import "github.com/praetorian-inc/janus-framework/pkg/chain"

type GcpOrganizationLister struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

func NewGcpOrganizationLister(configs ...cfg.Config) chain.Link {
	g := &GcpOrganizationLister{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrganizationLister) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	return err
}

func (g *GcpOrganizationLister) Process() error {
	searchReq := g.resourceManagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{})
	resp, err := searchReq.Do()
	if err != nil {
		return err
	}
	for _, org := range resp.Organizations {
		g.Send(gcpOrg)
	}
	return nil
}
```

**After (Native):**
```go
import "github.com/praetorian-inc/aurelian/pkg/plugin"

type GcpOrganizationLister struct {
	*base.NativeGCPLink
}

func NewGcpOrganizationLister(args map[string]any) *GcpOrganizationLister {
	return &GcpOrganizationLister{
		NativeGCPLink: base.NewNativeGCPLink("gcp-organization-lister", args),
	}
}

func (g *GcpOrganizationLister) Process(ctx context.Context, _ any) ([]any, error) {
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	searchReq := resourceManagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{})
	resp, err := searchReq.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}

	var results []any
	for _, org := range resp.Organizations {
		results = append(results, gcpOrg)
	}
	return results, nil
}

func (g *GcpOrganizationLister) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}
```

---

## Critical Implementation Notes

### 1. Helper Functions (DO NOT DUPLICATE)
These functions are shared within the `hierarchy` package and must stay in their original locations:

| Function | Location | Used By |
|----------|----------|---------|
| `createGcpOrgResource()` | organization.go | GcpOrganizationLister, GcpOrgInfoLink |
| `createGcpFolderResource()` | folders.go | GcpOrgFolderListLink, GcpFolderSubFolderListLink |
| `createGcpProjectResource()` | projects.go | GcpOrgProjectListLink, GcpFolderProjectListLink |
| `isSysProject()` | organization.go | GcpOrgProjectListLink |

**Important**: Do NOT copy these functions - they're package-scoped and already accessible.

### 2. Type Assertions Required
When input type is specific (not `any`), add type assertion:

```go
func (g *GcpOrgInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	orgName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}
	// ... use orgName
}
```

### 3. Service Creation Moved to Process
Initialize() deleted entirely - services created at start of Process():

```go
func (g *Link) Process(ctx context.Context, input any) ([]any, error) {
	service, err := gcpService.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}
	// ... use service
}
```

### 4. Native Base Provides
The `base.NativeGCPLink` already provides:
- `ClientOptions()` method - returns `[]option.ClientOption`
- `StandardGCPParams()` function - returns `[]plugin.Parameter` with project and credentials
- `ProjectID` and `CredentialsFile` fields

---

## Next Steps

1. **Migrate remaining 11 files** (3-4 hours estimated)
   - Apply transformation pattern from organization.go
   - Each file ~20 minutes (mechanical changes)
   
2. **Delete old base** 
   - Remove `pkg/links/gcp/base/gcp_base_link.go`
   
3. **Verify compilation**
   ```bash
   go build ./pkg/links/gcp/...
   ```
   
4. **Verify zero Janus imports**
   ```bash
   grep -r "janus-framework" pkg/links/gcp/ --include="*.go"
   # Expected: no output
   ```
   
5. **Run tests**
   ```bash
   go test ./pkg/links/gcp/...
   ```

---

## Exit Criteria

- [ ] All 13 files migrated/deleted
- [ ] Zero janus-framework imports in pkg/links/gcp/
- [ ] `go build ./pkg/links/gcp/...` succeeds
- [ ] All tests pass (if they exist)
- [ ] No compilation errors

---

## Risk Assessment

**Risk Level**: LOW

**Justification**:
- Pattern proven with organization.go (most complex file)
- Transformations are mechanical and repetitive
- Helper functions stay in place (no duplication risk)
- Native base already exists and tested
- Changes are isolated to pkg/links/gcp/ directory

**Mitigation**:
- Backups created for each file (.bak extension)
- Can rollback individual files if needed
- Compilation errors caught immediately

---

## Timeline Estimate

- **Remaining work**: 3-4 hours
- **Files per hour**: ~3 files
- **Completion target**: Single session possible

---

## References

- **Native base**: `/Users/nathansportsman/capabilities/modules/aurelian/pkg/links/gcp/base/native_base.go`
- **Completed example**: `/Users/nathansportsman/capabilities/modules/aurelian/pkg/links/gcp/hierarchy/organization.go`
- **Backup files**: `*.go.bak` in each directory
- **Full status report**: `/tmp/gcp-links-migration-status.md`
- **Migration plan**: `/tmp/gcp-links-migration-plan.txt`

---

**Prepared by**: capability-developer  
**Next action**: Continue migration with remaining 11 files following established pattern
