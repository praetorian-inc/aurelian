# Exhaustive Reuse Analysis Report

## Feature: AWS Links Migration to Native Plugin System

## Date: 2026-02-04T15:00:00Z

## Analyst: capability-developer

---

## COMPLIANCE CONFIRMATION

COMPLIANCE CONFIRMED: Exhaustive analysis performed, reuse prioritized over creation.

---

## SEARCH METHODOLOGY EXECUTED

### Commands Run

```bash
# Count total AWS link files
find pkg/links/aws -type f -name "*.go" | wc -l
# Found: 55 files

# List all subdirectories
find pkg/links/aws -type d | sort
# Found: 13 directories

# Count janus-framework import occurrences
grep -r "janus-framework" pkg/links/aws/ --include="*.go" | wc -l
# Found: 107 occurrences

# Find files with janus imports
grep -l "janus-framework" pkg/links/aws/*.go pkg/links/aws/*/*.go 2>/dev/null | sort
# Found: 47 files
```

### Coverage Verification

- [x] pkg/links/aws/ searched (55 files)
- [x] pkg/links/aws/base/ analyzed (3 files)
- [x] pkg/links/aws/ec2/ analyzed (2 files)
- [x] pkg/links/aws/ecr/ analyzed (5 files)
- [x] pkg/links/aws/cloudfront/ analyzed (3 files)
- [x] pkg/links/aws/lambda/ analyzed (2 files)
- [x] pkg/links/aws/cloudcontrol/ analyzed (2 files)
- [x] pkg/links/aws/cloudformation/ analyzed (1 file)
- [x] pkg/links/aws/cloudwatchlogs/ analyzed (1 file)
- [x] pkg/links/aws/cognito/ analyzed (1 file)
- [x] pkg/links/aws/ssm/ analyzed (1 file)
- [x] pkg/links/aws/stepfunctions/ analyzed (2 files)
- [x] pkg/links/aws/orgpolicies/ analyzed (2 files)
- [x] pkg/modules/ for migration pattern examples

---

## EXISTING IMPLEMENTATIONS DISCOVERED

### 100% Reusable (Use As-Is)

#### NativeAWSLink Base Implementation

- **File:** `pkg/links/aws/base/native_base.go`
- **Lines:** Complete implementation (48 lines)
- **Functionality:** Base struct for all AWS links with:
  - Profile and ProfileDir support
  - Regions configuration
  - GetConfig() method for AWS SDK config
  - StandardAWSParams() for common parameters
- **Evidence:** Already implements the exact pattern needed for migration
- **Reuse Strategy:** Import and embed `*base.NativeAWSLink` in all AWS link structs

```go
// Example from native_base.go lines 13-29
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

#### Plugin Registry Pattern

- **File:** `pkg/modules/azure/recon/public_resources.go` (lines 13-14)
- **Functionality:** Module registration via init()
- **Evidence:** `func init() { plugin.Register(&PublicResources{}) }`
- **Reuse Strategy:** Add init() to all migrated AWS links

### 80% Reusable (Extend)

#### N/A

No implementations found that need minor extension. The base is complete.

### 60% Reusable (Adapt)

#### Old AwsReconLink Base

- **File:** `pkg/links/aws/base/aws_recon_link.go`
- **Functionality:** Regions initialization logic, validation for global services
- **Adaptation Needed:** Extract region validation to helper or embed in NativeAWSLink
- **Refactor Strategy:** The validateResourceRegions() logic (lines 64-78) may need to be preserved as helper function

### 40% Reusable (Significant Refactor Needed)

#### Links Using chain.Link Interface

- **Examples:** 47 files throughout pkg/links/aws/
- **Pattern:** All use Janus chain.Link, cfg.Config, and Send() methods
- **Refactor Needed:** Convert from:
  - `chain.Link` → plugin Module interface
  - `cfg.Config` → `plugin.Config`
  - `Process(input)` → `Run(cfg plugin.Config) ([]plugin.Result, error)`
  - `Send(output)` → return `[]plugin.Result`
- **Estimated Effort:** ~30 minutes per file (mechanical transformation)

### 0% Reusable (New Code Required)

#### None

All patterns have existing implementations or clear migration paths.

---

## PATTERN INVENTORY

### Patterns Identified in Affected Area

#### Pattern 1: Janus Link Structure (OLD)

- **Location:** All 47 files in `pkg/links/aws/`
- **How it works:**
  ```go
  type AWSLink struct {
      *base.AwsReconLink
  }
  
  func NewAWSLink(configs ...cfg.Config) chain.Link {
      link := &AWSLink{}
      link.AwsReconLink = base.NewAwsReconLink(link, configs...)
      return link
  }
  
  func (a *AWSLink) Process(input *types.EnrichedResourceDescription) error {
      // ... AWS API calls ...
      a.Send(output)
      return nil
  }
  
  func (a *AWSLink) Params() []cfg.Param {
      return []cfg.Param{...}
  }
  ```

#### Pattern 2: Native Plugin Structure (NEW - TARGET)

- **Location:** `pkg/modules/azure/recon/` and `pkg/links/aws/base/native_base.go`
- **How it works:**
  ```go
  type AWSLink struct {
      *base.NativeAWSLink
  }
  
  func init() {
      plugin.Register(&AWSLink{})
  }
  
  func (m *AWSLink) ID() string { return "aws-link-id" }
  func (m *AWSLink) Name() string { return "AWS Link Name" }
  func (m *AWSLink) Description() string { return "..." }
  func (m *AWSLink) Platform() plugin.Platform { return plugin.PlatformAWS }
  func (m *AWSLink) Category() plugin.Category { return plugin.CategoryRecon }
  func (m *AWSLink) OpsecLevel() string { return "low" }
  func (m *AWSLink) Authors() []string { return []string{"Praetorian"} }
  func (m *AWSLink) References() []string { return []string{} }
  func (m *AWSLink) Parameters() []plugin.Parameter {
      return base.StandardAWSParams()
  }
  func (m *AWSLink) Run(cfg plugin.Config) ([]plugin.Result, error) {
      ctx := cfg.Context
      if ctx == nil {
          ctx = context.Background()
      }
      
      // Get AWS config using base helper
      awsCfg, err := m.GetConfig(ctx, region)
      if err != nil {
          return nil, err
      }
      
      // ... AWS API calls ...
      
      return []plugin.Result{
          {Data: output, Type: "json"},
      }, nil
  }
  ```
- **Extension point:** Embed `*base.NativeAWSLink`, implement plugin.Module interface

---

## MIGRATION STRATEGY

### Phase 1: Prioritize by Complexity

**Simple Links (Process single resource type):**
- ec2/ec2-userdata.go
- cognito/user_pool.go
- cloudwatchlogs/log_events.go
- ssm/list-parameters.go
- lambda/lambda_function_url.go

**Medium Links (Multiple API calls):**
- ec2/ec2_screenshot.go
- ecr/list-images.go
- cloudformation/cloudformation.go
- cloudfront/* files

**Complex Links (Apollo offline, CDK analysis):**
- apollo_* files
- cdk_* files
- resource_* aggregators/processors

### Phase 2: Migration Checklist Per File

For each file:
1. ✅ Replace `*base.AwsReconLink` with `*base.NativeAWSLink`
2. ✅ Remove Janus imports (chain, cfg, jtypes)
3. ✅ Add plugin imports
4. ✅ Add init() with plugin.Register()
5. ✅ Implement plugin.Module interface methods (ID, Name, Description, etc.)
6. ✅ Convert Parameters() to return []plugin.Parameter
7. ✅ Convert Process(input) to Run(cfg plugin.Config) ([]plugin.Result, error)
8. ✅ Replace a.Send(output) with return []plugin.Result{...}
9. ✅ Replace cfg.As[T]() with type assertions on cfg.Args
10. ✅ Use m.GetConfig(ctx, region) from NativeAWSLink

---

## INTEGRATION RECOMMENDATIONS

### Recommended Approach

**Incremental Migration with TDD:**

1. Start with simplest links (ec2-userdata.go)
2. Write test that exercises current functionality
3. Migrate to native pattern
4. Verify test still passes
5. Move to next file

**Key Decision: Keep or Delete Base Files?**

- **KEEP:** `pkg/links/aws/base/native_base.go` (100% reusable)
- **DELETE AFTER MIGRATION:** 
  - `pkg/links/aws/base/aws_recon_base_link.go` (old Janus base)
  - `pkg/links/aws/base/aws_recon_link.go` (old Janus base)

### Files to Modify (Extend Native Base)

**Option 1: Preserve region validation logic**
- Extract `validateResourceRegions()` from `aws_recon_link.go` to helper
- Or add to NativeAWSLink if needed by multiple links

**Option 2: Delete if unused**
- Verify if any link actually uses global service validation
- If not, delete the complexity

### Files to Migrate (47 files)

**Base directory (2 files - DELETE AFTER VERIFICATION):**
1. `base/aws_recon_base_link.go` - Old Janus base
2. `base/aws_recon_link.go` - Old Janus base

**Root directory (26 files):**
1. `access_key_to_account_id.go`
2. `account_auth_details.go`
3. `apollo_control_flow.go`
4. `apollo_offline_base_link.go`
5. `apollo_offline_control_flow.go`
6. `apollo_query.go`
7. `aws_resource_policy.go`
8. `cdk_bootstrap_checker.go`
9. `cdk_bucket_validator.go`
10. `cdk_policy_analyzer.go`
11. `cdk_qualifier_discovery.go`
12. `cdk_role_detector.go`
13. `console_url.go`
14. `erd_property_filter.go`
15. `find_secrets.go`
16. `gaad_file_loader.go`
17. `ip_lookup.go`
18. `known_account_id.go`
19. `public_resources.go`
20. `public_resources_processor.go`
21. `resource_aggregator.go`
22. `resource_chain_processor.go`
23. `resource_policies_file_loader.go`
24. `resource_policy_collector.go`
25. `resource_policy_with_arn_fetcher.go`
26. `resource_type_generator.go`
27. `summary.go`

**Subdirectories (19 files):**
- cloudcontrol/ (2 files)
- cloudformation/ (1 file)
- cloudfront/ (3 files)
- cloudwatchlogs/ (1 file)
- cognito/ (1 file)
- ec2/ (2 files)
- ecr/ (4 files)
- lambda/ (2 files)
- orgpolicies/ (1 file)
- ssm/ (1 file)
- stepfunctions/ (2 files)

### Anti-Patterns to Avoid

Based on existing codebase patterns:

- ❌ Do NOT create new base interfaces (NativeAWSLink already exists)
- ❌ Do NOT keep both old and new base implementations (delete old after migration)
- ❌ Do NOT mix Janus and native patterns in same file
- ❌ Do NOT forget init() registration (links won't be discovered)
- ❌ Do NOT simulate logic in tests (call actual Run() method)

---

## KEY FINDINGS

- **Reuse Percentage:** 100% for base pattern (native_base.go complete)
- **Files to Extend:** 0 (base is complete)
- **Files to Migrate:** 47 files
- **Files to Delete:** 2 files (old Janus base files after migration verification)
- **Critical Constraints:**
  - Must preserve AWS config/credential handling
  - Must maintain region validation for global services (or verify not needed)
  - Must ensure plugin registration for all links
  - Must convert Process() → Run() pattern consistently

---

## ESTIMATED EFFORT

**Per-file migration time:** ~20-30 minutes (mechanical transformation)

**Total estimated time:** 
- Simple links (5 files × 20 min): 1.7 hours
- Medium links (15 files × 25 min): 6.25 hours
- Complex links (27 files × 30 min): 13.5 hours
- **Total:** ~21.5 hours for complete migration

**Recommendation:** Break into batches of 5-10 files with verification checkpoints.

---

## NEXT STEPS

1. Get approval for migration strategy
2. Start with ec2/ec2-userdata.go (simplest file)
3. Write test, migrate, verify
4. Continue with batches of similar complexity
5. Delete old base files after all migrations verified
6. Run full test suite
7. Verify grep shows 0 janus-framework imports in pkg/links/aws/

