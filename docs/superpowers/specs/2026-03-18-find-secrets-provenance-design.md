# Find-Secrets Provenance Enrichment

## Problem

The find-secrets module stores provenance in the Titus SQLite DB as `FileProvenance{FilePath: label}`. This is a git/filesystem-oriented type that only carries a single path string. For cloud resources, critical context is lost:

- **CloudWatch Logs**: Label is `"log-event:{eventId}"` — an opaque ID with no log stream name. Users cannot determine which stream produced the finding without separate API calls.
- **All services**: The Titus DB contains no ARN, region, account ID, platform, or resource type. The only provenance visible in `titus explore` is the label string.

Rich cloud context exists in the Aurelian proof JSON output, but never reaches the Titus DB.

## Solution

Switch from `FileProvenance` to `ExtendedProvenance` across all three platforms (AWS, Azure, GCP). `ExtendedProvenance` stores a `map[string]any` payload in the Titus DB, carrying full cloud context. Consolidate the triplicated `buildProofData`/`riskFromScanResult` functions into the `secrets` package via methods on `SecretScanResult`.

The `titus explore` TUI will be updated separately to render `ExtendedProvenance` payloads.

## Design

### 1. Add `Platform` field to `ScanInput`

```go
// pkg/output/scan_input.go
type ScanInput struct {
    Content        []byte
    ResourceID     string
    ResourceType   string
    Region         string
    AccountID      string
    Label          string
    PathFilterable bool
    Platform       string // NEW: "aws", "azure", or "gcp"
}
```

Set in each constructor:

```go
func ScanInputFromAWSResource(r AWSResource, label string, content []byte) ScanInput {
    return ScanInput{
        Content:      content,
        ResourceID:   r.ARN,
        ResourceType: r.ResourceType,
        Region:       r.Region,
        AccountID:    r.AccountRef,
        Label:        label,
        Platform:     "aws",
    }
}
// Same pattern for ScanInputFromAzureResource ("azure") and ScanInputFromGCPResource ("gcp")
```

### 2. Add `Platform` field to `SecretScanResult`

```go
// pkg/secrets/scanner.go
type SecretScanResult struct {
    ResourceRef  string       `json:"resource_ref"`
    ResourceType string       `json:"resource_type"`
    Region       string       `json:"region"`
    AccountID    string       `json:"account_id"`
    Label        string       `json:"label"`
    Platform     string       `json:"platform"` // NEW
    Match        *types.Match `json:"match"`
}
```

Populated in `toScanResult` from `input.Platform`.

### 3. Switch to `ExtendedProvenance`

In `SecretScanner.Scan` (`pkg/secrets/scanner.go`):

```go
// Before
provenance := types.FileProvenance{FilePath: input.Label}

// After
provenance := types.ExtendedProvenance{
    Payload: map[string]any{
        "platform":      input.Platform,
        "resource_id":   input.ResourceID,
        "resource_type": input.ResourceType,
        "region":        input.Region,
        "account_id":    input.AccountID,
        "subresource":   input.Label,
    },
}
```

The payload is stored as JSON in the SQLite `path` column by the existing `AddProvenance` code path (sqlite.go:185-188).

### 4. Consolidate proof/risk logic into `secrets` package

Move the triplicated `buildProofData` and `riskFromScanResult` into the `secrets` package as methods on `SecretScanResult`:

```go
// pkg/secrets/risk.go

// proofData constructs proof JSON matching Guard's secrets proof format.
func (r SecretScanResult) proofData() map[string]any {
    proof := map[string]any{
        "finding_id":   r.Match.FindingID,
        "rule_name":    r.Match.RuleName,
        "rule_text_id": r.Match.RuleID,
        "resource_ref": r.ResourceRef,
        "num_matches":  1,
        "matches": []map[string]any{
            {
                "provenance": []map[string]any{
                    {
                        "kind":          "cloud_resource",
                        "platform":      r.Platform,
                        "resource_id":   r.ResourceRef,
                        "resource_type": r.ResourceType,
                        "region":        r.Region,
                        "account_id":    r.AccountID,
                        "first_commit": map[string]any{
                            "blob_path": r.Label,
                        },
                    },
                },
                "snippet": map[string]string{
                    "before":   string(r.Match.Snippet.Before),
                    "matching": string(r.Match.Snippet.Matching),
                    "after":    string(r.Match.Snippet.After),
                },
                "location": map[string]any{
                    "offset_span": map[string]any{
                        "start": r.Match.Location.Offset.Start,
                        "end":   r.Match.Location.Offset.End,
                    },
                    "source_span": map[string]any{
                        "start": map[string]any{
                            "line":   r.Match.Location.Source.Start.Line,
                            "column": r.Match.Location.Source.Start.Column,
                        },
                        "end": map[string]any{
                            "line":   r.Match.Location.Source.End.Line,
                            "column": r.Match.Location.Source.End.Column,
                        },
                    },
                },
            },
        },
    }

    if r.Match.ValidationResult != nil {
        proof["validation"] = map[string]any{
            "status":     string(r.Match.ValidationResult.Status),
            "confidence": r.Match.ValidationResult.Confidence,
            "message":    r.Match.ValidationResult.Message,
        }
    }

    return proof
}

// ToRisk converts a scan result into an AurelianRisk with marshalled proof.
func (r SecretScanResult) ToRisk() (output.AurelianRisk, error) {
    proofBytes, err := json.MarshalIndent(r.proofData(), "", "  ")
    if err != nil {
        return output.AurelianRisk{}, fmt.Errorf("marshalling proof: %w", err)
    }
    return newSecretRisk(r, proofBytes), nil
}

// RiskFromScanResult is a pipeline-compatible function that converts
// SecretScanResult to AurelianRisk and sends it to the output pipeline.
func RiskFromScanResult(result SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
    risk, err := result.ToRisk()
    if err != nil {
        slog.Warn("failed to build risk", "resource", result.ResourceRef, "error", err)
        return nil
    }
    out.Send(risk)
    return nil
}
```

`NewSecretRisk` becomes unexported `newSecretRisk` since callers now use `ToRisk()` or `RiskFromScanResult`. The `platform` parameter is removed — it reads from `r.Platform`.

### 5. Simplify per-module find_secrets.go

Each module deletes its local `buildProofData` and `riskFromScanResult`, replacing the pipeline wiring:

```go
// Before (in each module)
pipeline.Pipe(scanned, riskFromScanResult, out)

// After (all modules)
pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)
```

### 6. Fix CloudWatch Logs label

In `pkg/aws/extraction/extract_logs.go`, `extractLogStream`:

```go
// Before
label := "log-event"
if event.EventId != nil {
    label = "log-event:" + *event.EventId
}

// After
label := streamName
```

The stream name combined with the log group ARN (in `resource_id`) provides sufficient provenance to locate the source. EventIds are not directly queryable via AWS APIs and add no actionable value.

### 7. Remove legacy Go pattern

In `pkg/aws/extraction/extract_lambda.go:66`, remove the unnecessary `f := f` loop variable copy (Go 1.22+ has per-iteration scoping; project is on Go 1.25.3).

## ExtendedProvenance Payload Schema

Consistent across all platforms:

| Field | Type | Description | Example (AWS) | Example (Azure) | Example (GCP) |
|---|---|---|---|---|---|
| `platform` | string | Cloud provider | `"aws"` | `"azure"` | `"gcp"` |
| `resource_id` | string | Full resource identifier | `arn:aws:logs:...` | `/subscriptions/.../vm` | `projects/.../instances/...` |
| `resource_type` | string | Cloud-native type | `AWS::Logs::LogGroup` | `Microsoft.Compute/virtualMachines` | `compute.googleapis.com/Instance` |
| `region` | string | Geographic location | `us-east-1` | `eastus` | `us-central1-a` |
| `account_id` | string | Account scope | `123456789012` | subscription UUID | project ID |
| `subresource` | string | Location within resource | `my-stream-name` | `WebApp AppSettings` | `metadata/startup-script` |

## Migration / Backward Compatibility

- **Existing Titus DBs**: `BlobExists` check in `scanContent` means previously-scanned blobs retain their `file`-type provenance rows. New blobs get `extended`-type rows. This is a gradual migration — mixed types coexist safely.
- **Existing annotations**: Annotations are keyed by finding ID and match structural ID, not by provenance type. Annotations on existing findings are unaffected.
- **Proof JSON output**: The schema is identical — downstream consumers (Guard, reports) see no change. The `platform` field was already hardcoded per-module; now it comes from `SecretScanResult.Platform`.
- **titus explore TUI**: `ExtendedProvenance` currently has no render case in the type switch (details.go:183-206) and is silently skipped. The `File:` line will be absent for new findings until the TUI is updated. This is the accepted trade-off — TUI changes are a separate effort.

## Files Changed

| File | Change |
|---|---|
| `pkg/output/scan_input.go` | Add `Platform` field; set in all three `ScanInputFrom*` helpers |
| `pkg/secrets/scanner.go` | Add `Platform` to `SecretScanResult` and `toScanResult`; switch to `ExtendedProvenance` |
| `pkg/secrets/risk.go` | Add `proofData()` method, `ToRisk()` method, `RiskFromScanResult` function; unexport `newSecretRisk`; remove `platform` param |
| `pkg/modules/aws/recon/find_secrets.go` | Delete `buildProofData`, `riskFromScanResult`; use `secrets.RiskFromScanResult` |
| `pkg/modules/gcp/recon/find_secrets.go` | Delete `buildProofData`, `riskFromScanResult`; use `secrets.RiskFromScanResult` |
| `pkg/modules/azure/recon/find_secrets.go` | Delete `buildProofData`, `riskFromScanResult` (method on module); use `secrets.RiskFromScanResult` |
| `pkg/aws/extraction/extract_logs.go` | Change label from `"log-event:" + eventId` to `streamName` |
| `pkg/aws/extraction/extract_lambda.go` | Remove `f := f` loop variable copy |
| `pkg/modules/aws/recon/find_secrets_test.go` | Update tests to use `secrets.RiskFromScanResult` / `ToRisk()` |
| `pkg/modules/azure/recon/find_secrets_test.go` | Update tests to use `secrets.RiskFromScanResult` / `ToRisk()` |
| `pkg/modules/gcp/recon/find_secrets_test.go` | Update tests (if they test proof building) |

## Out of Scope

- `titus explore` TUI rendering of `ExtendedProvenance` (separate effort)
- Step Functions execution ARN enrichment (current label `execution:{name}` is adequate)
- Lambda version qualifier (returns `$LATEST` which is not actionable)
