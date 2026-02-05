# Aurelian Capability Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Complete the Janus framework removal by migrating all 48 modules to native Go plugin architecture with working Run() methods.

**Architecture:** Modules implement the `plugin.Module` interface and register via `init()`. Link logic from `pkg/links/` is inlined directly into module `Run()` methods or extracted to reusable functions in `pkg/utils/` or `internal/helpers/`.

**Tech Stack:** Go 1.24+, Azure SDK v2, AWS SDK v2, GCP Go SDK, NoseyParker (external binary)

---

## Executive Summary

### Current State

| Metric | Count |
|--------|-------|
| Total modules registered | 48 |
| Fully functional modules | ~35 |
| Incomplete modules (return "not implemented") | 13 |
| Link files with Process() methods | 45 |
| Link files total (including helpers) | 93 |

### Module Distribution by Platform

| Platform | Recon | Analyze | Secrets | Total |
|----------|-------|---------|---------|-------|
| AWS | 18 | 5 | 0 | 23 |
| Azure | 8 | 0 | 0 | 8 |
| GCP | 9 | 0 | 6 | 15 |
| SaaS | 1 | 0 | 0 | 1 |
| **Total** | 36 | 5 | 6 | **47** |

### Plugin Foundation (COMPLETE)

The native plugin architecture is already established in `pkg/plugin/`:

- `module.go` - Core Module interface (13 methods)
- `registry.go` - Thread-safe registry with init() self-registration
- `processor.go` - Pipeline pattern for composing operations
- `output.go` - Formatter interface for JSON/Console/Markdown output

---

## Incomplete Modules Inventory

### Priority 1: AWS Modules (5 modules)

| Module | File | Dependencies | Complexity |
|--------|------|--------------|------------|
| `find-secrets` | `aws/recon/find_secrets.go` | CloudControl, NoseyParker, resource preprocessing | High |
| `find-secrets-resource` | `aws/recon/find_secrets_resource.go` | SingleResourcePreprocessor, NoseyParker | Medium |
| `ecr-dump` | `aws/recon/ecr_dump.go` | CloudControl, Docker links | High |
| `apollo-offline` (partial) | `aws/recon/apollo_offline.go` | Neo4j integration | Medium |
| `ec2-screenshot-analysis` (partial) | `aws/recon/ec2_screenshot_analysis.go` | LLM analyzer | Medium |

### Priority 2: Azure Modules (5 modules)

| Module | File | Dependencies | Complexity |
|--------|------|--------------|------------|
| `find-secrets` | `azure/recon/find_secrets.go` | SubscriptionGenerator, NoseyParker | High |
| `find-secrets-resource` | `azure/recon/find_secrets_resource.go` | Resource preprocessing, NoseyParker | Medium |
| `arg-scan` | `azure/recon/arg_scan.go` | ARG templates, subscription generator | Medium |
| `summary` | `azure/recon/summary.go` | EnvironmentDetailsCollector | Medium |
| `role-assignments` | `azure/recon/role_assignments.go` | RoleAssignmentsCollector | Medium |

### Priority 3: GCP Modules (2 modules)

| Module | File | Dependencies | Complexity |
|--------|------|--------------|------------|
| `storage-secrets` | `gcp/secrets/scan_storage.go` | GCP Storage SDK, NoseyParker | High |
| Other secrets modules | `gcp/secrets/*.go` | Similar to storage-secrets | Medium |

### Priority 4: SaaS Modules (1 module)

| Module | File | Dependencies | Complexity |
|--------|------|--------------|------------|
| `docker-dump` | `saas/recon/docker_dump.go` | Docker links, NoseyParker | High |

---

## Link Dependency Analysis

### Link Categories

#### 1. Cloud API Links (Port to Helper Functions)

These links contain SDK calls that should become reusable functions:

**AWS Links (`pkg/links/aws/`):**
- `resource_type_generator.go` - CloudControl resource enumeration
- `resource_aggregator.go` - Result aggregation
- `summary.go` - Cost explorer integration
- `console_url.go` - Federation URL generation
- `account_auth_details.go` - GAAD parsing

**Azure Links (`pkg/links/azure/`):**
- `subscription_generator.go` - List subscriptions (already SDK-based)
- `resource_lister.go` - ARM resource listing
- `environment_details_collector.go` - Subscription details
- `conditional_access_collector.go` - Graph API for CA policies
- `role_assignments_collector.go` - RBAC enumeration

**GCP Links (`pkg/links/gcp/`):**
- `hierarchy/projects.go` - Project listing
- `hierarchy/folders.go` - Folder enumeration
- `storage/bucket.go` - Storage bucket operations
- `compute/instances.go` - VM enumeration

#### 2. Docker Links (Port to Internal Package)

Located in `pkg/links/docker/`:
- `pull.go` - Registry authentication and pull
- `save.go` - Image export to tar
- `extract.go` - Layer extraction
- `aggregator.go` - Result aggregation
- `helpers.go` - Utility functions

**Migration Target:** Create `internal/docker/` package with standalone functions.

#### 3. Output Formatting Links (Port to Formatters)

These links format output and should become Formatter implementations:
- `azure/summary_output_formatter.go`
- `azure/role_assignments_output_formatter.go`
- `azure/conditional_access_output_formatter.go`
- `azure/devops_output_formatter.go`

**Migration Target:** Extend `pkg/plugin/output.go` or create `pkg/outputters/` adapters.

#### 4. Preprocessor Links (Extract to Utils)

These links transform inputs:
- `general/generator.go` - Input generators
- `general/preprocess_resources.go` - Resource normalization
- `general/jq.go` - JQ filtering
- `general/unmarshal.go` - JSON unmarshaling

**Migration Target:** `pkg/utils/` or inline into modules.

---

## Migration Patterns

### Pattern A: Simple Cloud API Call

**Use when:** Module makes straightforward SDK calls without chaining.

**Example:** `aws/recon/whoami.go` (already complete)

```go
func (m *MyModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
    // 1. Parse config
    profile, _ := cfg.Args["profile"].(string)

    // 2. Create SDK client
    awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, nil, "stealth")
    if err != nil {
        return nil, fmt.Errorf("failed to get AWS config: %w", err)
    }

    // 3. Make API call
    client := service.NewFromConfig(awsCfg)
    result, err := client.SomeOperation(cfg.Context, &service.Input{})

    // 4. Return results
    return []plugin.Result{{Data: result}}, nil
}
```

### Pattern B: Multi-Step Pipeline (Use plugin.Pipeline)

**Use when:** Module chains multiple operations on input list.

**Example:** Secret scanning workflow

```go
func (m *MyModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
    // 1. Create pipeline
    pipeline := plugin.NewPipeline(
        plugin.ProcessorFunc(listResources),
        plugin.ProcessorFunc(extractContent),
        plugin.ProcessorFunc(scanSecrets),
    )

    // 2. Execute pipeline
    inputs := []any{cfg.Args["project-id"]}
    outputs, err := pipeline.Execute(cfg.Context, inputs)

    // 3. Convert to results
    return toResults(outputs), err
}
```

### Pattern C: Inline Link Logic

**Use when:** Link logic is specific to one module.

**Before (Janus Link):**
```go
type AzureSubscriptionGeneratorLink struct {
    *chain.Base
}

func (l *AzureSubscriptionGeneratorLink) Process(input any) error {
    subscriptions, _ := cfg.As[[]string](l.Arg("subscription"))
    cred, err := helpers.NewAzureCredential()
    // ... list subscriptions
    for _, sub := range allSubs {
        l.Send(sub)
    }
    return nil
}
```

**After (Inline Function):**
```go
func listAzureSubscriptions(ctx context.Context, input []string) ([]string, error) {
    if len(input) > 0 && !strings.EqualFold(input[0], "all") {
        return input, nil
    }

    cred, err := helpers.NewAzureCredential()
    if err != nil {
        return nil, err
    }

    client, err := armsubscriptions.NewClient(cred, nil)
    if err != nil {
        return nil, err
    }

    var subs []string
    pager := client.NewListPager(nil)
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            return nil, err
        }
        for _, sub := range page.Value {
            if sub.SubscriptionID != nil {
                subs = append(subs, *sub.SubscriptionID)
            }
        }
    }
    return subs, nil
}
```

### Pattern D: Extract to Shared Helper

**Use when:** Logic is used by multiple modules.

**Target:** `internal/helpers/` or `pkg/utils/`

```go
// internal/helpers/azure.go
func ListSubscriptions(ctx context.Context, filter []string) ([]string, error)
func GetResourcesInSubscription(ctx context.Context, subID string) ([]Resource, error)

// internal/helpers/secrets.go
func ScanWithNoseyParker(ctx context.Context, paths []string) ([]Finding, error)
```

---

## Phase 1: Foundation (Prerequisites)

### Task 1.1: Create NoseyParker Integration

**Files:**
- Create: `internal/secrets/noseyparker.go`
- Create: `internal/secrets/noseyparker_test.go`

**Dependencies:** External `noseyparker` binary

**Implementation:**
```go
// internal/secrets/noseyparker.go
package secrets

import (
    "context"
    "encoding/json"
    "os/exec"
)

type Finding struct {
    Rule     string `json:"rule"`
    Location string `json:"location"`
    Match    string `json:"match"`
}

func ScanPath(ctx context.Context, path string) ([]Finding, error) {
    cmd := exec.CommandContext(ctx, "noseyparker", "scan",
        "--datastore", "/tmp/np-datastore",
        "--git-url", path,
        "-f", "json",
    )
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var findings []Finding
    if err := json.Unmarshal(output, &findings); err != nil {
        return nil, err
    }
    return findings, nil
}

func ScanContent(ctx context.Context, content []byte) ([]Finding, error) {
    // Write to temp file, scan, cleanup
}
```

**Exit Criteria:**
- [ ] `internal/secrets/noseyparker.go` exists with `ScanPath()` and `ScanContent()` functions
- [ ] Unit tests pass for both functions
- [ ] Integration test with real `noseyparker` binary passes

### Task 1.2: Create Docker Integration

**Files:**
- Create: `internal/docker/client.go`
- Create: `internal/docker/extract.go`
- Create: `internal/docker/client_test.go`

**Source Logic:** Port from `pkg/links/docker/`:
- `pull.go` - Registry pull with auth
- `save.go` - Image save to tar
- `extract.go` - Layer extraction from tar

**Exit Criteria:**
- [ ] `internal/docker/client.go` with `PullImage()`, `SaveImage()` functions
- [ ] `internal/docker/extract.go` with `ExtractLayers()` function
- [ ] Unit tests for all functions

### Task 1.3: Verify Azure Helper Functions

**File:** `internal/helpers/azure.go`

**Check existing functions:**
- `NewAzureCredential()` - Already exists
- `ListSubscriptions()` - Need to add or verify

**Exit Criteria:**
- [ ] `ListSubscriptions(ctx, filter []string)` function exists and works
- [ ] `GetEnvironmentDetails(ctx, subscriptionID)` function exists

---

## Phase 2: AWS Module Completion

### Task 2.1: aws/recon/find-secrets

**File:** `pkg/modules/aws/recon/find_secrets.go`

**Current State:** Returns "module implementation pending" error

**Link Dependencies:**
- `aws/resource_type_generator.go` - Resource enumeration
- `general/preprocess_resources.go` - Resource normalization
- NoseyParker integration

**Implementation Steps:**

1. **Get AWS configuration**
   ```go
   profile, _ := cfg.Args["profile"].(string)
   awsCfg, err := helpers.GetAWSCfg(region, profile, nil, "moderate")
   ```

2. **List resources by type**
   ```go
   resourceTypes, _ := cfg.Args["resource-type"].([]string)
   for _, resType := range resourceTypes {
       resources, err := cloudcontrol.ListResources(ctx, awsCfg, resType)
       // Process each resource
   }
   ```

3. **Extract content from resources**
   - Lambda: Get function code
   - SSM: Get parameter values
   - CloudFormation: Get template
   - EC2: Get user data
   - ECS: Get task definition

4. **Scan with NoseyParker**
   ```go
   findings, err := secrets.ScanContent(ctx, content)
   ```

5. **Return aggregated results**

**Exit Criteria:**
- [ ] Module executes without "not implemented" error
- [ ] Can scan Lambda functions for secrets
- [ ] Can scan SSM parameters for secrets
- [ ] Can scan CloudFormation stacks for secrets
- [ ] Integration test with real AWS credentials passes

### Task 2.2: aws/recon/find-secrets-resource

**File:** `pkg/modules/aws/recon/find_secrets_resource.go`

**Current State:** Returns TODO indicating implementation needed

**Implementation:** Same as find-secrets but for single resource ARN input.

**Exit Criteria:**
- [ ] Accepts single resource ARN as input
- [ ] Correctly routes to appropriate content extraction
- [ ] Returns NoseyParker findings

### Task 2.3: aws/recon/ecr-dump

**File:** `pkg/modules/aws/recon/ecr_dump.go`

**Current State:** Returns TODO indicating implementation needed

**Dependencies:**
- CloudControl for ECR repository listing
- Docker integration for image pull/extract

**Implementation Steps:**
1. List ECR repositories via CloudControl
2. Get authentication token for ECR
3. Pull each image using Docker client
4. Extract layers
5. Scan with NoseyParker

**Exit Criteria:**
- [ ] Lists ECR repositories successfully
- [ ] Authenticates to ECR
- [ ] Pulls and extracts images
- [ ] Scans for secrets

### Task 2.4: aws/recon/apollo-offline (Partial)

**File:** `pkg/modules/aws/recon/apollo_offline.go`

**Current State:** Mostly complete, but Neo4j integration has TODO

**Link Dependencies:**
- `aws/apollo_offline_control_flow.go` - Processing logic
- `aws/apollo_offline_base_link.go` - Base functionality

**Missing:** Direct Neo4j relationship creation

**Exit Criteria:**
- [ ] Neo4j relationship creation works
- [ ] Full offline analysis completes

### Task 2.5: aws/recon/ec2-screenshot-analysis (Partial)

**File:** `pkg/modules/aws/recon/ec2_screenshot_analysis.go`

**Current State:** Functional for capture, LLM analysis incomplete

**Dependencies:**
- `llm/anthropic_analyzer.go` - LLM integration

**Exit Criteria:**
- [ ] LLM analysis of screenshots works
- [ ] Returns structured analysis results

---

## Phase 3: Azure Module Completion

### Task 3.1: azure/recon/find-secrets

**File:** `pkg/modules/azure/recon/find_secrets.go`

**Current State:** Returns TODO indicating implementation needed

**Link Dependencies:**
- `azure/subscription_generator.go` - Subscription listing
- `azure/resource_lister.go` - ARM resource listing
- Resource-specific secrets extractors
- NoseyParker integration

**Implementation Steps:**

1. **List subscriptions**
   ```go
   subs, err := listAzureSubscriptions(ctx, subscriptionFilter)
   ```

2. **For each subscription, list resources**
   ```go
   for _, sub := range subs {
       resources, err := listAzureResources(ctx, sub, resourceTypes)
   }
   ```

3. **Extract secrets by resource type**
   - VMs: User data, extensions
   - Web Apps: Configuration, connection strings
   - Key Vault: Secrets (if accessible)
   - Automation Accounts: Variables, runbooks

4. **Scan with NoseyParker**

**Exit Criteria:**
- [ ] Lists subscriptions successfully
- [ ] Enumerates resources in subscriptions
- [ ] Extracts content from supported resource types
- [ ] Returns NoseyParker findings

### Task 3.2: azure/recon/find-secrets-resource

**File:** `pkg/modules/azure/recon/find_secrets_resource.go`

**Current State:** Returns TODO indicating implementation needed

**Implementation:** Single resource version of find-secrets

**Exit Criteria:**
- [ ] Accepts single Azure resource ID
- [ ] Extracts content appropriately
- [ ] Returns findings

### Task 3.3: azure/recon/arg-scan

**File:** `pkg/modules/azure/recon/arg_scan.go`

**Current State:** Returns TODO indicating implementation needed

**Link Dependencies:**
- `azure/subscription_generator.go` - Subscription listing
- `azure/arg_template.go` - ARG query execution
- `azure/enricher/` - Resource enrichment

**Implementation Steps:**

1. **List subscriptions**
2. **Load ARG templates** (embedded or from directory)
3. **Execute ARG queries per subscription**
4. **Enrich results with additional data**
5. **Format output**

**Exit Criteria:**
- [ ] Executes embedded ARG templates
- [ ] Can use custom template directory
- [ ] Returns enriched resource data

### Task 3.4: azure/recon/summary

**File:** `pkg/modules/azure/recon/summary.go`

**Current State:** Returns TODO indicating implementation needed

**Link Dependencies:**
- `azure/environment_details_collector.go` - Subscription details
- `azure/summary_output_formatter.go` - Output formatting

**Implementation:**
```go
func (m *Summary) Run(cfg plugin.Config) ([]plugin.Result, error) {
    subs, err := listAzureSubscriptions(ctx, filter)

    var summaries []EnvironmentSummary
    for _, sub := range subs {
        details, err := collectEnvironmentDetails(ctx, sub)
        summaries = append(summaries, details)
    }

    return formatSummaryResults(summaries), nil
}
```

**Exit Criteria:**
- [ ] Collects subscription details
- [ ] Returns resource counts by type
- [ ] Formats output correctly

### Task 3.5: azure/recon/role-assignments

**File:** `pkg/modules/azure/recon/role_assignments.go`

**Current State:** Returns TODO indicating implementation needed

**Link Dependencies:**
- `azure/role_assignments_collector.go` - RBAC enumeration
- `azure/role_assignments_output_formatter.go` - Output formatting

**Exit Criteria:**
- [ ] Enumerates role assignments per subscription
- [ ] Includes principal details
- [ ] Formats output correctly

---

## Phase 4: GCP Module Completion

### Task 4.1: gcp/secrets/storage-secrets

**File:** `pkg/modules/gcp/secrets/scan_storage.go`

**Current State:** Returns "not implemented" errors for all helper functions

**Link Dependencies:**
- `gcp/hierarchy/projects.go` - Project info
- `gcp/storage/bucket.go` - Bucket operations
- NoseyParker integration

**Implementation:**

1. **Get project info**
   ```go
   import "cloud.google.com/go/storage"

   client, err := storage.NewClient(ctx)
   ```

2. **List buckets**
   ```go
   it := client.Buckets(ctx, projectID)
   for {
       bucket, err := it.Next()
       if err == iterator.Done {
           break
       }
   }
   ```

3. **List objects and scan**
   ```go
   query := &storage.Query{}
   it := bucket.Objects(ctx, query)
   for {
       obj, err := it.Next()
       // Download and scan
   }
   ```

**Exit Criteria:**
- [ ] `getProjectInfo()` returns valid project details
- [ ] `listStorageBuckets()` returns bucket list
- [ ] `listStorageObjects()` returns object list
- [ ] `downloadObject()` retrieves object content
- [ ] `scanForSecrets()` integrates NoseyParker
- [ ] Full workflow executes end-to-end

### Task 4.2: Complete Other GCP Secrets Modules

Similar pattern for:
- `scan_cloud_run.go`
- `scan_functions.go`
- `scan_app_engine.go`
- `scan_artifactory.go`
- `scan_instances.go`

**Exit Criteria:**
- [ ] All 6 GCP secrets modules execute without "not implemented" error

---

## Phase 5: SaaS Module Completion

### Task 5.1: saas/recon/docker-dump

**File:** `pkg/modules/saas/recon/docker_dump.go`

**Current State:** Returns "not implemented" for helper functions

**Dependencies:**
- `internal/docker/` (from Task 1.2)
- `internal/secrets/` (from Task 1.1)

**Implementation:**

```go
func (m *DockerDump) Run(cfg plugin.Config) ([]plugin.Result, error) {
    image := cfg.Args["docker-image"].(string)
    user, _ := cfg.Args["docker-user"].(string)
    password, _ := cfg.Args["docker-password"].(string)

    // 1. Pull image
    imagePath, err := docker.PullImage(ctx, image, user, password)
    if err != nil {
        return nil, err
    }
    defer os.RemoveAll(imagePath)

    // 2. Extract layers
    extractDir, err := docker.ExtractLayers(ctx, imagePath)
    if err != nil {
        return nil, err
    }
    defer os.RemoveAll(extractDir)

    // 3. Scan for secrets
    findings, err := secrets.ScanPath(ctx, extractDir)
    if err != nil {
        return nil, err
    }

    return []plugin.Result{{
        Data: map[string]any{
            "image":    image,
            "findings": findings,
        },
    }}, nil
}
```

**Exit Criteria:**
- [ ] `loadDockerImage()` pulls images with auth
- [ ] `extractLayers()` extracts tar layers
- [ ] `scanForSecrets()` runs NoseyParker
- [ ] Full workflow completes

---

## Phase 6: Link Cleanup

### Task 6.1: Archive Unused Links

After all modules are migrated, archive links that are no longer needed:

```bash
# Create archive directory
mkdir -p pkg/links/_archived

# Move Janus-dependent links
mv pkg/links/azure/*.go pkg/links/_archived/ # except enrichers
mv pkg/links/aws/*.go pkg/links/_archived/
mv pkg/links/gcp/*.go pkg/links/_archived/
mv pkg/links/docker/*.go pkg/links/_archived/
mv pkg/links/general/*.go pkg/links/_archived/
```

**Exit Criteria:**
- [ ] All modules still compile and run
- [ ] No imports of `janus-framework/pkg/chain`
- [ ] Archived links preserved for reference

### Task 6.2: Remove Janus Framework Dependency

**File:** `go.mod`

```bash
# Remove Janus framework
go mod edit -droprequire github.com/praetorian-inc/janus-framework
go mod tidy
```

**Exit Criteria:**
- [ ] `go.mod` has no Janus framework reference
- [ ] `go build ./...` succeeds
- [ ] All tests pass

---

## Verification

### Test Each Module

For each completed module, verify:

```bash
# Build CLI
go build -o aurelian ./cmd/

# Test module exists in CLI
./aurelian list-modules | grep <module-id>

# Test module execution (with appropriate credentials)
./aurelian <platform> <category> <module-id> --help
./aurelian <platform> <category> <module-id> [args]
```

### Integration Tests

Create integration tests for complex workflows:

```go
// test/integration/aws_find_secrets_test.go
func TestAWSFindSecrets(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }

    cfg := plugin.Config{
        Context: context.Background(),
        Args: map[string]any{
            "resource-type": []string{"AWS::Lambda::Function"},
            "profile":       os.Getenv("AWS_PROFILE"),
        },
    }

    module := &recon.FindSecrets{}
    results, err := module.Run(cfg)

    require.NoError(t, err)
    assert.NotEmpty(t, results)
}
```

---

## Complexity Estimates

| Phase | Tasks | Estimated Effort | Notes |
|-------|-------|-----------------|-------|
| Phase 1 | 3 | 2-3 hours | Foundation work |
| Phase 2 | 5 | 4-6 hours | AWS modules, most complex |
| Phase 3 | 5 | 4-5 hours | Azure modules |
| Phase 4 | 2 | 2-3 hours | GCP modules, similar pattern |
| Phase 5 | 1 | 1-2 hours | Docker integration |
| Phase 6 | 2 | 1-2 hours | Cleanup |
| **Total** | **18** | **14-21 hours** | |

---

## Success Criteria

### Per-Module Verification

For each of the 13 incomplete modules:

- [ ] `Run()` method executes without "not implemented" error
- [ ] Returns valid `[]plugin.Result` with appropriate data
- [ ] Handles errors gracefully
- [ ] Respects context cancellation
- [ ] Unit tests pass

### Global Verification

- [ ] All 48 modules registered in CLI
- [ ] `go build ./...` succeeds with no Janus imports
- [ ] All existing tests pass
- [ ] No regression in working modules

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-02-04T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/aurelian",
  "skills_invoked": [
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "gateway-backend",
    "gateway-integrations",
    "writing-plans",
    "discovering-reusable-code"
  ],
  "source_files_verified": [
    "pkg/plugin/module.go",
    "pkg/plugin/registry.go",
    "pkg/plugin/processor.go",
    "pkg/plugin/output.go",
    "pkg/modules/aws/recon/whoami.go",
    "pkg/modules/aws/recon/find_secrets.go",
    "pkg/modules/azure/recon/find_secrets.go",
    "pkg/modules/gcp/secrets/scan_storage.go",
    "pkg/modules/saas/recon/docker_dump.go",
    "pkg/links/azure/subscription_generator.go",
    "pkg/links/docker/extract.go",
    "pkg/links/options/aws_opts.go",
    "pkg/links/options/azure_options.go",
    "pkg/links/options/gcp_options.go"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Execute phases in order. Phase 1 creates shared infrastructure (NoseyParker, Docker). Phases 2-5 complete individual modules. Phase 6 removes Janus dependency."
  }
}
```
