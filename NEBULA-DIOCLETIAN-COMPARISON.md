# Nebula vs Diocletian: Architectural Comparison

**Date:** 2026-01-23
**Purpose:** Document the key differences between Nebula and Diocletian cloud security scanning tools

---

## Executive Summary

Diocletian is a complete rewrite of Nebula following the standalone CLI pattern used by `fingerprintx`, `nuclei`, and `go-cicd`. The core difference is **separation of concerns**:

- **Nebula**: Tightly coupled to Chariot via shared Tabularium types and Neo4j key generation
- **Diocletian**: Loosely coupled via CLI interface, outputs pure domain data, graph concerns live in Chariot

This allows Diocletian to run as a completely standalone security scanning tool while Chariot handles all graph database integration.

---

## 1. Architectural Pattern

| Aspect | Nebula | Diocletian |
|--------|--------|------------|
| **Integration Model** | Embedded library (imported by Chariot) | Standalone CLI (invoked via `exec.Command`) |
| **Type Dependencies** | Uses **Tabularium** types directly (`model.AWSResource`, `model.GraphModel`) | Uses **pure domain types** in `pkg/output/` - NO Tabularium imports |
| **Neo4j Key Generation** | Keys generated inside tool via `GetKey()` methods | **NO key generation** - Chariot generates keys from pure domain data |
| **Output Destination** | Returns Go structs to caller | Outputs JSON to stdout, files to `diocletian-output/` |

### Invocation Pattern

**Nebula (Embedded Library):**
```go
// Chariot imports Diocletian as library
import diocletianMods "github.com/praetorian-inc/diocletian/pkg/modules"
mod := diocletianMods.AWSPublicResourcesSingle
mod.Run(cfg)
```

**Diocletian (Standalone CLI):**
```bash
# Chariot invokes Diocletian as CLI
diocletian aws public-resources --profile prod --output-format json | chariot-parser
```

---

## 2. Type System Differences

### Nebula Type System

**Location:** `pkg/types/enriched_resource_description.go`

```go
// HAS Tabularium dependency
import "github.com/praetorian-inc/tabularium/pkg/model/model"

type EnrichedResourceDescription struct {
    Identifier string      `json:"Identifier"`
    TypeName   string      `json:"TypeName"`
    Region     string      `json:"Region"`
    Properties interface{} `json:"Properties"`
    AccountId  string      `json:"AccountId"`
    Arn        arn.ARN     `json:"Arn"`
}

// Converts to Tabularium type
func (e *EnrichedResourceDescription) ToAWSResource() (*model.AWSResource, error) {
    awsResource, err := model.NewAWSResource(...)  // Creates Tabularium type
    return &awsResource, nil
}
```

### Diocletian Type System

**Location:** `pkg/output/types.go`

```go
// NO Tabularium imports - pure domain types
type CloudResource struct {
    Platform     string         `json:"platform"`       // "aws", "azure", "gcp"
    ResourceType string         `json:"resource_type"`  // "AWS::S3::Bucket"
    ResourceID   string         `json:"resource_id"`    // ARN
    AccountRef   string         `json:"account_ref"`    // Account ID
    Region       string         `json:"region,omitempty"`
    DisplayName  string         `json:"display_name,omitempty"`
    Properties   map[string]any `json:"properties,omitempty"`
    URLs         []string       `json:"urls,omitempty"`
    IPs          []string       `json:"ips,omitempty"`
    // NO GetKey() method - Chariot generates keys
}

type SecretFinding struct {
    ResourceRef string `json:"resource_ref"`
    RuleName    string `json:"rule_name"`
    RuleTextID  string `json:"rule_text_id"`
    Match       string `json:"match,omitempty"`
    FilePath    string `json:"file_path,omitempty"`
    LineNumber  int    `json:"line_number,omitempty"`
    Confidence  string `json:"confidence"`
}

type Risk struct {
    Target         *CloudResource `json:"target,omitempty"`
    Name           string         `json:"name"`
    DNS            string         `json:"dns"`
    Status         string         `json:"status"`  // TL/TM/TH/TC severity
    Source         string         `json:"source"`
    Description    string         `json:"description"`
    Impact         string         `json:"impact"`
    Recommendation string         `json:"recommendation"`
    References     string         `json:"references"`
}
```

---

## 3. Relationship Handling

### Nebula Relationships

Uses `model.GraphRelationship` from Tabularium with pre-computed keys.

### Diocletian Relationships

**Location:** `pkg/output/relationships.go`

```go
// ResourceRef identifies a resource without Neo4j key knowledge.
// This is pure domain data - Chariot generates keys from this.
type ResourceRef struct {
    Platform string `json:"platform"` // "aws", "azure", "gcp"
    Type     string `json:"type"`     // "iam-user", "s3-bucket", etc.
    ID       string `json:"id"`       // ARN or resource path
    Account  string `json:"account"`  // Account/subscription/project
}

// IAMPermission represents an IAM permission - pure domain data
// NO Neo4j key knowledge - Chariot generates keys
type IAMPermission struct {
    Source     ResourceRef    `json:"source"`
    Target     ResourceRef    `json:"target"`
    Permission string         `json:"permission"`           // "s3:GetObject"
    Effect     string         `json:"effect,omitempty"`     // "Allow" or "Deny"
    Conditions map[string]any `json:"conditions,omitempty"` // IAM policy conditions
    Capability string         `json:"capability"`           // Scanner identifier
    Timestamp  string         `json:"timestamp"`            // ISO 8601 format
}

type SSMPermission struct {
    IAMPermission
    SSMDocumentRestrictions []string `json:"ssm_document_restrictions,omitempty"`
    AllowsShellExecution    bool     `json:"allows_shell_execution"`
}

type GitHubActionsPermission struct {
    IAMPermission
    SubjectPatterns []string `json:"subject_patterns,omitempty"`
    RepositoryOrg   string   `json:"repository_org,omitempty"`
    RepositoryName  string   `json:"repository_name,omitempty"`
}
```

---

## 4. CLI Output Flags

| Flag | Nebula | Diocletian | Notes |
|------|--------|------------|-------|
| `--output` | Directory path | N/A | Different approach |
| `--outfile` | Filename | N/A | Different approach |
| `--output-format` | N/A | `json`/`markdown`/`default` | Diocletian-specific |
| `--indent` | JSON indentation | N/A | Nebula only |
| `--log-level` | Yes | Yes | Same |
| `--quiet` | Yes | Yes | Same |
| `--no-color` | Yes | Yes | Same |
| Output location | `nebula-output/` | `diocletian-output/` | Default directories |

### AWS-Specific Flags (Identical)

| Flag | Both Tools |
|------|------------|
| `-r, --regions` | Yes |
| `-t, --resource-type` | Yes |
| `-p, --profile` | Yes |
| `--profile-dir` | Yes |
| `--cache-dir` | Yes |
| `--cache-ttl` | Yes |
| `--disable-cache` | Yes |

---

## 5. Tabularium Import Comparison

### Nebula: 20+ Files Import Tabularium

```
nebula/pkg/outputters/neo4j_graph_outputter.go
nebula/pkg/outputters/risk_console_outputter.go
nebula/pkg/outputters/risk_csv_outputter.go
nebula/pkg/outputters/screenshot_outputter.go
nebula/pkg/outputters/arg_scan_output.go
nebula/pkg/outputters/azure_resource_outputter.go
nebula/pkg/types/enriched_resource_description.go
nebula/pkg/modules/aws/recon/ec2_screenshot_analysis.go
nebula/pkg/modules/aws/recon/ecr_dump.go
nebula/pkg/links/gcp/hierarchy/folders.go
nebula/pkg/links/gcp/hierarchy/organization.go
nebula/pkg/links/gcp/hierarchy/projects.go
nebula/pkg/links/gcp/storage/bucket.go
nebula/pkg/links/gcp/storage/sql.go
nebula/pkg/links/general/preprocess_resources.go
nebula/pkg/links/aws/cdk_bootstrap_checker.go
nebula/pkg/links/aws/cdk_bucket_validator.go
nebula/pkg/links/aws/cdk_policy_analyzer.go
...
```

### Diocletian: ZERO Production Code Imports

- Only indirect dependency via janus-framework
- All 57 migrated files use pure domain types from `pkg/output/`

**Verification:**
```bash
cd modules/diocletian
grep -r "tabularium" pkg --include="*.go" | grep -v "_test.go"
# Expected: empty output
```

---

## 6. Key Generation Responsibility

### Nebula: Generates Neo4j Keys Internally

```go
// From nebula's neo4j_graph_outputter.go
func (o *Neo4jGraphOutputter) tabullariumNodeToGraphNode(node model.GraphModel) *graph.Node {
    properties := make(map[string]interface{})
    properties["key"] = node.GetKey()  // Key computed by Nebula
    // ...
}
```

### Diocletian: Chariot Generates Keys

```go
// From diocletian STATUS.md - Key generation happens in Chariot parser
// Location: modules/chariot/backend/pkg/lib/diocletian_cli/parser.go (to be created)

func generateKey(ref ResourceRef) string {
    return fmt.Sprintf("#%sresource#%s#%s", ref.Platform, ref.Account, ref.ID)
}
```

**Key format:**
```
#awsresource#{account}#{arn}
#azureresource#{subscription}#{resource_id}
#gcpresource#{project}#{resource_path}
```

---

## 7. Project Structure Comparison

```
nebula/pkg/                              diocletian/pkg/
├── types/                               ├── output/
│   ├── enriched_resource_description.go │   ├── types.go          # Pure domain types
│   ├── aws_gaad_struct.go               │   ├── types_test.go
│   ├── aws_policy_struct.go             │   ├── relationships.go  # NO tabularium
│   └── result.go                        │   └── relationships_test.go
│       (imports tabularium)             │
├── outputters/                          ├── outputters/
│   ├── neo4j_graph_outputter.go         │   ├── json_stream.go    # NDJSON streaming
│   ├── risk_console_outputter.go        │   ├── neo4j_graph_outputter.go
│   └── (10+ outputters)                 │   └── (17 outputters)
│       (imports tabularium)             │
├── links/                               ├── links/
│   ├── aws/ (50+ files)                 │   ├── aws/ (55+ files, migrated)
│   ├── azure/                           │   ├── azure/ (27 files)
│   └── gcp/                             │   └── gcp/ (11 files)
├── modules/                             ├── modules/
│   └── aws/recon/                       │   └── aws/recon/ (22 AWS modules)
└── iam/aws/                             │
    └── (IAM analysis)                   └── (IAM integrated into links)
```

---

## 8. Module Command Inventory

Both tools have **22 identical AWS modules**:

| Category | Module ID | Type |
|----------|-----------|------|
| **recon** | whoami | auto-run |
| **recon** | account-auth-details | auto-run |
| **recon** | list | input |
| **recon** | list-all | input |
| **recon** | summary | auto-run |
| **recon** | public-resources | input |
| **recon** | public-resources-single | input |
| **recon** | apollo | input |
| **recon** | apollo-offline | input |
| **recon** | find-secrets | input |
| **recon** | find-secrets-resource | input |
| **recon** | resource-policies | auto-run |
| **recon** | org-policies | auto-run |
| **recon** | get-console | input |
| **recon** | ecr-dump | auto-run |
| **recon** | cdk-bucket-takeover | auto-run |
| **recon** | cloudfront-s3-takeover | auto-run |
| **recon** | ec2-screenshot-analysis | input |
| **analyze** | ip-lookup | input |
| **analyze** | access-key-to-account-id | input |
| **analyze** | known-account-id | input |
| **analyze** | apollo-query | input |
| **analyze** | expand-actions | input |

---

## 9. Migration Status

### Completed (Phase 0)

| Task | Status | Details |
|------|--------|---------|
| Task 1: Remove Tabularium Dependency | ✅ Complete | 57 files migrated |
| Task 2: Add JSON CLI Output Mode | ✅ Complete | `pkg/outputters/json_stream.go` |
| Task 2b: Wire Outputter to CLI Flag | ✅ Complete | `cmd/output_selector.go` |
| Task 2c: P0 CLI Fixes | ✅ Complete | Exit codes, stderr, auto-quiet |

### Remaining

| Phase | Task | Status | Location |
|-------|------|--------|----------|
| Phase 0 | Task 3: Create Chariot Parser | Not Started | `modules/chariot/backend/pkg/lib/diocletian_cli/` |
| Phase 1 | Capability Wrapper Migration | Not Started | `modules/chariot/backend/pkg/tasks/capabilities/` |
| Phase 2 | Cleanup Old Adapter Layer | Not Started | Delete `modules/chariot/backend/pkg/lib/diocletian/` |

---

## 10. Data Flow Comparison

### Nebula Data Flow (Embedded)

```
┌─────────────────┐    Go structs    ┌─────────────────┐    Direct calls   ┌─────────────────┐
│   Nebula        │ ───────────────> │   Chariot       │ ────────────────> │   Neo4j         │
│   (Library)     │                  │   (Caller)      │                   │   Database      │
│                 │                  │                 │                   │                 │
│ - Tabularium    │                  │ - Receives      │                   │ - Pre-computed  │
│   types         │                  │   model.*       │                   │   keys          │
│ - GetKey()      │                  │   types         │                   │                 │
└─────────────────┘                  └─────────────────┘                   └─────────────────┘
```

### Diocletian Data Flow (Standalone)

```
┌─────────────────┐     NDJSON      ┌─────────────────┐    Graph ops     ┌─────────────────┐
│   Diocletian    │ ──────────────> │   Chariot       │ ───────────────> │   Neo4j         │
│   CLI           │   Pure Domain   │   Parser        │                  │   Database      │
│                 │   Data          │                 │                  │                 │
│ NO Neo4j keys   │                 │ Generates keys  │                  │ Keys from       │
│ NO Tabularium   │                 │ Creates models  │                  │ Chariot         │
└─────────────────┘                 └─────────────────┘                  └─────────────────┘
```

---

## 11. Benefits of Diocletian Architecture

| Benefit | Description |
|---------|-------------|
| **Standalone Capability** | Can run as independent security tool without Chariot |
| **Loose Coupling** | CLI interface allows independent versioning/deployment |
| **Scalability** | Unlimited concurrency via process spawning |
| **Resource Cleanup** | Process termination handles cleanup automatically |
| **Testing** | Easier to test in isolation with JSON fixtures |
| **Pattern Consistency** | Matches fingerprintx, nuclei, go-cicd patterns |
| **Domain Purity** | Output types know nothing about graph concerns |

---

## 12. Related Documentation

- **Comparison Test Plan:** `NEBULA-DIOCLETIAN-AWS-COMPARISON-PLAN.md`
- **Migration Status:** `STATUS.md`
- **Handoff Document:** `HANDOFF.md`
- **Master Plan:** `.claude/.output/capabilities/20260104-195038-diocletian-refactoring-analysis/MASTER-REFACTORING-PLAN.md`
- **Architecture Decision:** `.claude/.output/capabilities/20260104-195038-diocletian-refactoring-analysis/ARCHITECTURE-QA.md`
