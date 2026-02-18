# Design: Unified `AWSIAMResource` Output Type

## Goal

Consolidate the 3 result sets from `graph.go` (GAAD, cloud resources, IAM relationships) into 2 (entities, relationships) by introducing an `AWSIAMResource` type that wraps `CloudResource` with typed IAM fields. All internal analyzer machinery remains untouched — conversion happens only at the output boundary.

---

## New Type

**File:** `pkg/output/aws_iam_resource.go`

```go
type AWSIAMResource struct {
    CloudResource

    // IAM-specific typed fields (nil for non-IAM resources)
    InlinePolicies          []iam.PrincipalPL   `json:"inline_policies,omitempty"`
    AttachedManagedPolicies []iam.ManagedPL      `json:"attached_managed_policies,omitempty"`
    PermissionsBoundary     *iam.ManagedPL       `json:"permissions_boundary,omitempty"`
    AssumeRolePolicy        *types.Policy        `json:"assume_role_policy,omitempty"`
    InstanceProfiles        []iam.InstanceProfile `json:"instance_profiles,omitempty"`
    PolicyVersions          []iam.PoliciesVL     `json:"policy_versions,omitempty"`
    GroupMemberships        []string             `json:"group_memberships,omitempty"`
    Tags                    []iam.Tag            `json:"tags,omitempty"`
}
```

**Why in `output` package:** `CloudResource` lives there already; this is an output concern, not an analyzer concern. However, this creates an import of `iam` types from `output`. If that's a circular dependency problem, the type moves to a new `pkg/output/aws` subpackage or to `pkg/aws/iam/output.go`.

---

## Conversion Functions

**File:** `pkg/output/aws_iam_resource.go` (or `pkg/aws/iam/converters.go` if import direction requires it)

```
FromUserDL(user UserDL, accountID string) AWSIAMResource
FromRoleDL(role RoleDL) AWSIAMResource
FromGroupDL(group GroupDL) AWSIAMResource
FromPolicyDL(policy PoliciesDL) AWSIAMResource
FromCloudResource(cr CloudResource) AWSIAMResource   // wraps non-IAM resources (nil IAM fields)
```

Each populates the embedded `CloudResource` fields (Platform, ResourceType, ResourceID, ARN, AccountRef, Region) and the typed IAM fields. Example for `FromUserDL`:

- `CloudResource.ResourceType` = `"AWS::IAM::User"`
- `CloudResource.ARN` = `user.Arn`
- `CloudResource.DisplayName` = `user.UserName`
- `InlinePolicies` = `user.UserPolicyList`
- `AttachedManagedPolicies` = `user.AttachedManagedPolicies`
- `PermissionsBoundary` = `&user.PermissionsBoundary` (if non-zero)
- `GroupMemberships` = `user.GroupList`
- `Tags` = `user.Tags`

For non-IAM cloud resources, `FromCloudResource` simply embeds the `CloudResource` with all IAM fields nil.

---

## Changed Files

### 1. `pkg/modules/aws/recon/graph.go`

**Before:** Returns 3 results — `gaadData`, `allResources`, `fullResults`

**After:** Returns 2 results — `[]AWSIAMResource`, `[]FullResult`

At the end of `Run()`, after the analyzer completes:

```go
// Convert GAAD entities to AWSIAMResource
var entities []AWSIAMResource
for _, user := range gaadData.UserDetailList { entities = append(entities, FromUserDL(user, accountID)) }
for _, role := range gaadData.RoleDetailList { entities = append(entities, FromRoleDL(role)) }
for _, group := range gaadData.GroupDetailList { entities = append(entities, FromGroupDL(group)) }
for _, policy := range gaadData.Policies { entities = append(entities, FromPolicyDL(policy)) }

// Convert cloud resources to AWSIAMResource (IAM fields nil)
for _, cr := range resourcesList { entities = append(entities, FromCloudResource(cr)) }

// Deduplicate: IAM resources appear in both GAAD and CloudControl
// GAAD version wins (has typed IAM fields). Dedup by ARN.
entities = deduplicateByARN(entities)
```

Return:

```go
Result{Data: entities, Metadata: {"type": "entities", ...}}
Result{Data: fullResults, Metadata: {"type": "iam_relationships", ...}}
```

### 2. `pkg/modules/aws/analyze/analyze_iam_permissions.go`

Same pattern — convert at the end. Since this module only has GAAD (no cloud resources), it only converts GAAD entities:

```go
Result{Data: entities, Metadata: ...}    // []AWSIAMResource from GAAD only
Result{Data: results, Metadata: ...}     // []FullResult (unchanged)
```

This changes it from 1 result to 2, which is a minor API change but aligns both modules.

### 3. `pkg/plugin/graph_formatter.go`

**Before:** Type-switches on `*iampkg.Gaad`, `[]output.CloudResource`, `map[string][]output.CloudResource`, `[]iampkg.FullResult`

**After:** Type-switches on `[]output.AWSIAMResource` and `[]iampkg.FullResult`

Node creation changes from:

```go
// OLD: separate paths for GAAD and CloudResource
for _, user := range gaad.UserDetailList { nodes = append(nodes, NodeFromGaadUser(user)) }
for _, role := range gaad.RoleDetailList { nodes = append(nodes, NodeFromGaadRole(role)) }
for _, group := range gaad.GroupDetailList { nodes = append(nodes, NodeFromGaadGroup(group)) }
for _, resource := range resources { nodes = append(nodes, NodeFromCloudResource(resource)) }
```

To:

```go
// NEW: single path
for _, entity := range entities { nodes = append(nodes, NodeFromAWSIAMResource(entity)) }
```

### 4. `pkg/graph/transformers/aws/aws.go`

**Add:** `NodeFromAWSIAMResource(resource AWSIAMResource) *graph.Node`

This function inspects `resource.ResourceType` and delegates:

| ResourceType | Delegation |
|---|---|
| `AWS::IAM::User` | Existing `NodeFromGaadUser` logic (extracts labels `["User", "Principal", ...]`) |
| `AWS::IAM::Role` | Existing `NodeFromGaadRole` logic (extracts `trusted_services`) |
| `AWS::IAM::Group` | Existing `NodeFromGaadGroup` logic |
| Everything else | Existing `NodeFromCloudResource(resource.CloudResource)` |

The existing `NodeFromGaad*` and `NodeFromCloudResource` functions stay as-is for backward compatibility. `NodeFromAWSIAMResource` is a router that calls them (converting `AWSIAMResource` back to the expected input types).

### 5. `pkg/plugin/graph_formatter_test.go`

Update test fixtures to provide `[]AWSIAMResource` instead of `*Gaad` + `[]CloudResource`.

---

## What Does NOT Change

- `pkg/aws/iam/types_gaad.go` — `Gaad`, `UserDL`, `RoleDL`, `GroupDL`, `PoliciesDL` structs
- `pkg/aws/iam/gaad_analyzer.go` — all analyzer internals
- `pkg/aws/iam/analyzer_state.go` — all caches and state
- `pkg/aws/iam/evaluator.go` — `PolicyData`, `PolicyEvaluator`
- `pkg/aws/iam/full_result.go` — `FullResult` struct and `PermissionsSummary.FullResults()`
- `pkg/aws/iam/erd_constructors.go` — `NewEnrichedResourceDescriptionFrom*`
- `pkg/aws/gaad/collector.go` — GAAD collection
- `pkg/types/enriched_resource_description.go` — `EnrichedResourceDescription`
- `pkg/aws/iam/permissions_summary.go`
- `pkg/aws/iam/create_then_use.go`
- All test files for analyzer internals

---

## Deduplication Concern

GAAD and CloudControl both discover IAM entities (users, roles, groups). The `erd_constructors.go` already handles this for the `ResourceCache` in the analyzer. At the output boundary we need the same: when an entity appears in both GAAD and cloud resources, keep the GAAD-sourced `AWSIAMResource` (it has the typed IAM fields). Simple ARN-keyed map, GAAD entities inserted first, cloud resources only added if ARN not already present.

---

## Import Direction

```
output ← (no iam dependency if we keep conversion functions in iam package)
iam → output (iam already imports output indirectly via types)
```

Safest placement: conversion functions in `pkg/aws/iam/converters.go`, new type in `pkg/output/aws_iam_resource.go` with no `iam` import (IAM fields use generic types or interfaces).

Actually, the cleanest option: put `AWSIAMResource` in `pkg/output/` but define the IAM-specific fields using the same primitive types already in `output` — just `map[string]any` for the policy documents. Then the conversion functions in `pkg/aws/iam/converters.go` know how to populate them from typed GAAD structs.

**Alternative:** Put everything (`AWSIAMResource` + converters) in a new `pkg/aws/iam/output/` subpackage. This avoids any circular dependency risk entirely.

---

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Circular imports between `output` and `iam` | Place type + converters carefully per import direction above |
| GAAD/CloudControl deduplication misses edge cases | Dedup by ARN; GAAD wins; log conflicts |
| `GraphFormatter` consumers expect 3 results | Only `graph_formatter.go` consumes; we update it |
| `FullResult.Principal` still embeds `UserDL`/`RoleDL` | Unchanged — `FullResult` is a relationship type, not an entity type |
| Existing JSON output format changes for `graph` module | Breaking change for anyone parsing the 3-result JSON. Document in changelog. |
