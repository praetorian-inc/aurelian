# Azure Links Migration Plan
## Aurelian Janus Unbinding - pkg/links/azure/

**Status**: ~26% complete (per lead review 2026-02-04)
**Location**: `/Users/nathansportsman/capabilities/modules/aurelian/pkg/links/azure/`
**Scope**: 47 Go files (61 janus-framework imports remaining)

---

## Migration Pattern (Verified)

### Base Infrastructure ✅ COMPLETE
- `pkg/links/azure/base/native_base.go` - Already migrated
- Provides `NativeAzureLink` struct with:
  - `*plugin.BaseLink` embedding
  - Azure-specific fields (SubscriptionID, TenantID)
  - `GetCredential()` helper
  - `StandardAzureParams()` helper

### Per-File Migration Steps

**For each file in pkg/links/azure/*.go:**

1. **Update struct embedding**:
   ```go
   // OLD:
   type XxxLink struct {
       *chain.Base
   }

   // NEW:
   type XxxLink struct {
       *base.NativeAzureLink
   }
   ```

2. **Remove Janus imports**:
   ```go
   // REMOVE:
   "github.com/praetorian-inc/janus-framework/pkg/chain"
   "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
   jtypes "github.com/praetorian-inc/janus-framework/pkg/types"

   // ADD:
   "context"
   "github.com/praetorian-inc/aurelian/pkg/links/azure/base"
   "github.com/praetorian-inc/aurelian/pkg/plugin"
   ```

3. **Update constructor**:
   ```go
   // OLD:
   func NewXxxLink(configs ...cfg.Config) chain.Link {
       l := &XxxLink{}
       l.Base = chain.NewBase(l, configs...)
       return l
   }

   // NEW:
   func NewXxxLink(args map[string]any) *XxxLink {
       return &XxxLink{
           NativeAzureLink: base.NewNativeAzureLink("xxx-link", args),
       }
   }
   ```

4. **Add plugin registration**:
   ```go
   func init() {
       plugin.RegisterLink("xxx-link", func(args map[string]any) plugin.Link {
           return NewXxxLink(args)
       })
   }
   ```

5. **Update Process method signature**:
   ```go
   // OLD:
   func (l *XxxLink) Process(input *output.CloudResource) error

   // NEW:
   func (l *XxxLink) Process(ctx context.Context, input any) ([]any, error)
   ```

6. **Convert Params() → Parameters()**:
   ```go
   // OLD:
   func (l *XxxLink) Params() []cfg.Param {
       return []cfg.Param{
           options.AzureSubscription(),
       }
   }

   // NEW:
   func (l *XxxLink) Parameters() []plugin.Parameter {
       return base.StandardAzureParams()
   }
   ```

7. **Replace l.Send() with return values**:
   ```go
   // OLD:
   l.Send(npInput)
   return nil

   // NEW:
   var results []any
   results = append(results, npInput)
   return results, nil
   ```

8. **Replace l.Context() with passed ctx**:
   ```go
   // OLD:
   pager.NextPage(l.Context())

   // NEW:
   pager.NextPage(ctx)
   ```

9. **Update Logger access**:
   ```go
   // OLD:
   l.Logger.Error(...)

   // NEW:
   l.Logger().Error(...)
   ```

---

## File Inventory (45 files)

### Core Links (15 files)
- [ ] automation_secrets.go
- [ ] azure_find_secrets.go
- [ ] azure_resource_chain_processor.go
- [ ] container_registry_secrets.go
- [ ] function_app_secrets.go
- [ ] keyvault_secrets.go
- [ ] resource_aggregator.go
- [ ] resource_lister.go
- [ ] role_assignments_collector.go
- [ ] storage_secrets.go
- [ ] subscription_generator.go
- [ ] webapp_secrets.go
- [ ] environment_details_collector.go
- [ ] arg_template.go
- [ ] summary_output_formatter.go

### DevOps Links (7 files)
- [ ] devops_auth.go
- [ ] devops_output_formatter.go
- [ ] devops_pipelines.go
- [ ] devops_project_discovery.go
- [ ] devops_repo_scan.go
- [ ] devops_service_endpoints.go
- [ ] devops_variable_groups.go

### Conditional Access Links (7 files)
- [ ] conditional_access_aggregator.go
- [ ] conditional_access_analysis_output_formatter.go
- [ ] conditional_access_collector.go
- [ ] conditional_access_file_loader.go
- [ ] conditional_access_llm_analyzer.go
- [ ] conditional_access_output_formatter.go
- [ ] conditional_access_resolver.go

### Role Assignments Links (1 file)
- [ ] role_assignments_output_formatter.go

### Enricher Submodules (15 files in pkg/links/azure/enricher/)
- [ ] enricher/aks_cluster.go
- [ ] enricher/app_service.go
- [ ] enricher/arg_enricher.go
- [ ] enricher/container_registry.go
- [ ] enricher/cosmos_db.go
- [ ] enricher/database_allow_azure_services.go
- [ ] enricher/event_grid.go
- [ ] enricher/event_hub.go
- [ ] enricher/key_vault.go
- [ ] enricher/redis_cache.go
- [ ] enricher/registry.go
- [ ] enricher/service_bus.go
- [ ] enricher/sql_server.go
- [ ] enricher/storage_account.go
- [ ] enricher/virtual_machine.go

---

## Testing Strategy

### Per-File Testing
After migrating each file:
1. Run: `go build ./pkg/links/azure/`
2. Check compilation errors
3. Verify no janus-framework imports remain

### Integration Testing
After batch completion (every 10 files):
1. Run: `go test ./pkg/links/azure/...`
2. Verify tests pass or identify needed test updates
3. Check for runtime "not implemented" errors

### Final Verification
After all files migrated:
```bash
# Must return 0:
grep -r "janus-framework" pkg/links/azure/ | wc -l

# Must return 0:
grep -r "chain\.Base" pkg/links/azure/ | wc -l

# Must compile:
go build ./...

# Tests should pass:
go test ./pkg/links/azure/...
```

---

## Estimated Effort

**Per file**: ~30-60 minutes (varies by complexity)
- Simple links (single Process method): 20-30 min
- Complex links (multiple helpers): 45-60 min
- Enrichers (often simpler): 15-30 min

**Total estimate**: 40-60 hours (confirmed by lead review)

**Blockers**:
- Some modules may need additional helper functions
- Output type conversions (jtypes.NPInput → plugin.Result)
- Context threading through existing helper methods

---

## Migration Order (Recommended)

1. **Phase 1**: Simple single-method links (automation_secrets, keyvault_secrets, storage_secrets)
2. **Phase 2**: Resource aggregation (resource_lister, resource_aggregator, subscription_generator)
3. **Phase 3**: DevOps suite (7 devops_*.go files)
4. **Phase 4**: Conditional access suite (7 conditional_access_*.go files)
5. **Phase 5**: Enricher submodules (15 enricher/*.go files)
6. **Phase 6**: Complex links (azure_resource_chain_processor, azure_find_secrets)

---

## Current Status

**Completed**: Base infrastructure (native_base.go)
**Remaining**: 45 link files + test files
**Janus imports**: 61 remaining in pkg/links/azure/

**Next Steps**:
1. Start with automation_secrets.go (sample migration)
2. Verify pattern works end-to-end
3. Document any pattern adjustments needed
4. Proceed through phases 1-6 systematically

---

## Notes from Lead Review (2026-02-04)

> **What's NOT Done (Critical)**:
> - `pkg/links/` (~95 files) still import janus-framework
> - 11+ modules return "not implemented" errors at runtime
> - janus-framework still in go.mod (144 files import it)

This migration is part of the larger Aurelian unbinding effort. The Azure links represent ~47 of the ~95 remaining link files.
