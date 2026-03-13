# CloudFront S3 Takeover — Pipeline Input Refactor

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the cloudfront-s3-takeover module to accept both single-resource ARN input and list-all-distributions input, following the same pipeline architecture as public-resources and find-secrets.

**Architecture:** Replace the monolithic `Scan()` function with two pipeline-compatible components: a `Lister` (routes ARN→single distribution, resource type→all distributions) and a `Checker` (validates S3 origins, queries Route53). The module's `Run()` chains these via `pipeline.Pipe`, matching the established pattern. Config changes from `AWSReconBase` to `AWSCommonRecon` to gain `ResourceARN`, `ResourceType`, `Regions`, and `Concurrency` parameters.

**Tech Stack:** Go 1.25, AWS SDK v2, Aurelian pipeline framework

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `pkg/aws/cloudfront/lister.go` | **Create** | Pipeline-compatible distribution lister — routes identifiers to single-fetch or full enumeration |
| `pkg/aws/cloudfront/checker.go` | **Create** | Pipeline-compatible vulnerability checker — S3 bucket existence + Route53 record matching per distribution |
| `pkg/modules/aws/recon/cloudfront_s3_takeover.go` | **Rewrite** | Module wiring — config, pipeline chain, risk conversion |
| `pkg/aws/cloudfront/scan.go` | **Delete** | Monolithic Scan() replaced by Lister + Checker |
| `test/integration/aws/recon/cloudfront_s3_takeover_test.go` | **Modify** | Adapt to new config shape (minimal change) |
| `pkg/aws/cloudfront/types.go` | **Modify** | Remove `ScanOptions` and `ScanResult` (dead after scan.go deletion); all other types preserved |
| `pkg/aws/cloudfront/distributions.go` | Unchanged | `enumerateDistributions`, `buildDistributionInfo`, pure helpers — reused by Lister |
| `pkg/aws/cloudfront/buckets.go` | **Modify** | Remove `findVulnerableDistributions` (dead after scan.go deletion); `checkBucketExists`, `checkDistributionOrigins` preserved for Checker |
| `pkg/aws/cloudfront/route53.go` | Unchanged | `findRoute53Records` — reused by Checker |
| `pkg/aws/cloudfront/distributions_test.go` | Unchanged | Existing unit tests still valid |
| `pkg/aws/cloudfront/route53_test.go` | Unchanged | Existing unit tests still valid |
| `test/terraform/aws/recon/cloudfront-s3-takeover/` | Unchanged | Terraform fixture stays the same |

**Key constraint:** CloudFront is a global service — all SDK clients always use `us-east-1` regardless of the `Regions` config parameter. The module creates a single `aws.Config` in `us-east-1` and passes it to both Lister and Checker, avoiding duplicate STS calls.

---

## Chunk 1: Lister + Checker Components

### Task 1: Create the Lister

**Files:**
- Create: `pkg/aws/cloudfront/lister.go`

The Lister routes input identifiers to either single-distribution fetch or full enumeration. Its `List` method has the pipeline-compatible signature `func(string, *pipeline.P[DistributionInfo]) error`.

**Input routing logic** (mirrors `CloudControlLister.List` in `pkg/aws/cloudcontrol/list.go:40-52`):
- If identifier parses as an ARN → extract distribution ID from resource part (`distribution/DIST_ID`), call `GetDistribution`, emit one `DistributionInfo`
- If identifier starts with `"AWS::"` → call existing `enumerateDistributions` to list all, emit each

**Reference:** The existing `enumerateDistributions` function in `distributions.go:87-122` takes a `CloudFrontAPI` interface (satisfied by `*cloudfront.Client`) and returns `[]DistributionInfo`. The `buildDistributionInfo` helper at `distributions.go:125-163` converts SDK responses.

- [ ] **Step 1: Write `pkg/aws/cloudfront/lister.go`**

```go
package cloudfront

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	cfclient "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Lister enumerates CloudFront distributions via the pipeline interface.
// It handles both single-distribution ARN input and full enumeration.
type Lister struct {
	cfClient  CloudFrontAPI
	accountID string
}

// NewLister creates a Lister from a pre-configured CloudFront client.
func NewLister(cfClient *cfclient.Client, accountID string) *Lister {
	return &Lister{
		cfClient:  cfClient,
		accountID: accountID,
	}
}

// List routes an identifier to single-distribution fetch or full enumeration.
// Satisfies the pipeline.Pipe function signature: func(string, *pipeline.P[DistributionInfo]) error.
func (l *Lister) List(identifier string, out *pipeline.P[DistributionInfo]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		return l.listByARN(parsed, out)
	}

	if strings.HasPrefix(identifier, "AWS::") {
		return l.listAll(out)
	}

	return fmt.Errorf("identifier must be an ARN or CloudControl resource type: %q", identifier)
}

// listByARN fetches a single distribution by ARN and emits it.
// CloudFront ARN format: arn:aws:cloudfront::ACCOUNT_ID:distribution/DIST_ID
func (l *Lister) listByARN(parsed awsaarn.ARN, out *pipeline.P[DistributionInfo]) error {
	distID, err := parseDistributionID(parsed.Resource)
	if err != nil {
		return err
	}

	slog.Debug("fetching single distribution", "id", distID)

	resp, err := l.cfClient.GetDistribution(context.Background(), &cfclient.GetDistributionInput{
		Id: &distID,
	})
	if err != nil {
		return fmt.Errorf("get distribution %s: %w", distID, err)
	}

	info := buildDistributionInfo(resp, l.accountID)
	out.Send(info)
	return nil
}

// listAll enumerates every distribution in the account and emits each.
func (l *Lister) listAll(out *pipeline.P[DistributionInfo]) error {
	slog.Info("enumerating all CloudFront distributions", "account", l.accountID)

	dists, err := enumerateDistributions(context.Background(), l.cfClient, l.accountID)
	if err != nil {
		return fmt.Errorf("enumerate distributions: %w", err)
	}

	slog.Info("found distributions", "count", len(dists))
	for _, d := range dists {
		out.Send(d)
	}
	return nil
}

// parseDistributionID extracts the distribution ID from an ARN resource field.
// Expected format: "distribution/EDFDVBD632BHDS5"
func parseDistributionID(resource string) (string, error) {
	prefix := "distribution/"
	after, found := strings.CutPrefix(resource, prefix)
	if !found || after == "" {
		return "", fmt.Errorf("invalid CloudFront ARN resource %q: expected %s<id>", resource, prefix)
	}
	return after, nil
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/aws/cloudfront/...`
Expected: clean compile

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/cloudfront/lister.go
git commit -m "feat(cloudfront): add pipeline-compatible distribution Lister"
```

---

### Task 2: Create the Checker

**Files:**
- Create: `pkg/aws/cloudfront/checker.go`

The Checker validates each distribution for vulnerable S3 origins and matches Route53 records. Its `Check` method has the pipeline-compatible signature `func(DistributionInfo, *pipeline.P[Finding]) error`.

**Reuses existing functions:**
- `checkDistributionOrigins` in `buckets.go:65-94` — returns `[]VulnerableDistribution` for missing S3 buckets
- `findRoute53Records` in `route53.go:23-96` — returns `[]Route53Record` for matching DNS records

- [ ] **Step 1: Write `pkg/aws/cloudfront/checker.go`**

```go
package cloudfront

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Checker validates CloudFront distributions for S3 origin takeover vulnerabilities.
type Checker struct {
	s3Client  S3API
	r53Client Route53API
}

// NewChecker creates a Checker from pre-configured S3 and Route53 clients.
func NewChecker(s3Client *s3.Client, r53Client *route53.Client) *Checker {
	return &Checker{
		s3Client:  s3Client,
		r53Client: r53Client,
	}
}

// Check validates a single distribution's S3 origins and emits a Finding for
// each missing bucket. Satisfies the pipeline.Pipe function signature:
// func(DistributionInfo, *pipeline.P[Finding]) error.
func (c *Checker) Check(dist DistributionInfo, out *pipeline.P[Finding]) error {
	vulnerable := checkDistributionOrigins(context.Background(), c.s3Client, dist)

	for _, vuln := range vulnerable {
		records, err := findRoute53Records(context.Background(), c.r53Client, vuln.DistributionDomain, vuln.Aliases)
		if err != nil {
			slog.Warn("error searching Route53 records", "distribution", vuln.DistributionID, "error", err)
			records = nil
		}

		out.Send(Finding{
			VulnerableDistribution: vuln,
			Route53Records:         records,
		})
	}

	return nil
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/aws/cloudfront/...`
Expected: clean compile

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/cloudfront/checker.go
git commit -m "feat(cloudfront): add pipeline-compatible vulnerability Checker"
```

---

## Chunk 2: Module Rewrite + Cleanup

### Task 3: Rewrite the module

**Files:**
- Modify: `pkg/modules/aws/recon/cloudfront_s3_takeover.go`

Changes:
1. Config: `AWSReconBase` → `AWSCommonRecon` (gains `ResourceARN`, `ResourceType`, `Regions`, `Concurrency`)
2. `Run()`: create AWS config once, construct Lister + Checker, wire pipeline chain
3. `buildTakeoverRisk`: adapt to pipeline function signature `func(cf.Finding, *pipeline.P[model.AurelianModel]) error`
4. `collectAffectedDomains`: stays as-is (internal helper)

**Reference patterns:**
- `public_resources.go:61-86` — pipeline chain with `collectInputs` → `lister.List` → pipeline stages → `out.Wait()`
- `helper.go:33-44` — `collectInputs(opts, supportedTypes)` returns ARNs or resource types

- [ ] **Step 1: Rewrite `cloudfront_s3_takeover.go`**

Full replacement content:

```go
package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cf "github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSCloudFrontS3TakeoverModule{})
}

type CloudFrontS3TakeoverConfig struct {
	plugin.AWSCommonRecon
}

type AWSCloudFrontS3TakeoverModule struct {
	CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) ID() string                { return "cloudfront-s3-takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Name() string              { return "CloudFront S3 Origin Takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSCloudFrontS3TakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSCloudFrontS3TakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *AWSCloudFrontS3TakeoverModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSCloudFrontS3TakeoverModule) Description() string {
	return "Detects CloudFront distributions with S3 origins pointing to non-existent buckets, " +
		"which could allow attackers to take over the domain by creating the missing bucket. " +
		"Also identifies Route53 records pointing to vulnerable distributions."
}

func (m *AWSCloudFrontS3TakeoverModule) References() []string {
	return []string{
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
		"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
		"https://github.com/EdOverflow/can-i-take-over-xyz",
	}
}

func (m *AWSCloudFrontS3TakeoverModule) SupportedResourceTypes() []string {
	return []string{"AWS::CloudFront::Distribution"}
}

func (m *AWSCloudFrontS3TakeoverModule) Parameters() any {
	return &m.CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.CloudFrontS3TakeoverConfig

	// CloudFront is a global service — always us-east-1.
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	inputs, err := collectInputs(c.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("collect inputs: %w", err)
	}

	lister := cf.NewLister(cloudfront.NewFromConfig(awsCfg), accountID)
	checker := cf.NewChecker(s3.NewFromConfig(awsCfg), route53.NewFromConfig(awsCfg))

	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[cf.DistributionInfo]()
	pipeline.Pipe(inputPipeline, lister.List, listed)

	findings := pipeline.New[cf.Finding]()
	pipeline.Pipe(listed, checker.Check, findings)

	pipeline.Pipe(findings, buildTakeoverRisk, out)
	return out.Wait()
}

func buildTakeoverRisk(f cf.Finding, out *pipeline.P[model.AurelianModel]) error {
	severity := output.RiskSeverityMedium
	if len(f.Route53Records) > 0 {
		severity = output.RiskSeverityHigh
	}

	affectedDomains := collectAffectedDomains(f.Aliases, f.Route53Records)

	description := fmt.Sprintf(
		"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content.",
		f.DistributionID, f.MissingBucket,
	)
	if len(f.Route53Records) > 0 {
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"Route53 records are actively pointing to this distribution. "+
				"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			f.DistributionID, f.MissingBucket,
			len(affectedDomains), strings.Join(affectedDomains, ", "),
		)
	} else if len(affectedDomains) > 0 {
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"An attacker could create this bucket to serve malicious content on alias domain(s): %s",
			f.DistributionID, f.MissingBucket,
			strings.Join(affectedDomains, ", "),
		)
	}

	ctx, err := json.Marshal(map[string]any{
		"distribution_id":     f.DistributionID,
		"distribution_domain": f.DistributionDomain,
		"missing_bucket":      f.MissingBucket,
		"origin_domain":       f.OriginDomain,
		"origin_id":           f.OriginID,
		"aliases":             f.Aliases,
		"affected_domains":    affectedDomains,
		"route53_records":     f.Route53Records,
		"description":         description,
		"impact": "An attacker could register the missing S3 bucket and serve arbitrary content " +
			"through the CloudFront distribution, enabling subdomain or domain takeover.",
		"recommendation": fmt.Sprintf(
			"1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
				"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
				"3. Update the distribution to point to a different, existing origin.",
			f.DistributionID, f.MissingBucket,
		),
	})
	if err != nil {
		slog.Warn("failed to marshal risk context", "distribution", f.DistributionID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        "cloudfront-s3-takeover",
		Severity:    severity,
		ImpactedARN: f.DistributionID,
		Context:     ctx,
	})
	return nil
}

func collectAffectedDomains(aliases []string, records []cf.Route53Record) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, r := range records {
		if !seen[r.RecordName] {
			seen[r.RecordName] = true
			domains = append(domains, r.RecordName)
		}
	}
	for _, alias := range aliases {
		if !seen[alias] {
			seen[alias] = true
			domains = append(domains, alias)
		}
	}
	return domains
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/modules/aws/recon/...`
Expected: clean compile

- [ ] **Step 3: Commit**

```bash
git add pkg/modules/aws/recon/cloudfront_s3_takeover.go
git commit -m "refactor(cloudfront): rewrite module with pipeline chain and AWSCommonRecon config"
```

---

### Task 4: Delete scan.go and remove dead code

**Files:**
- Delete: `pkg/aws/cloudfront/scan.go`
- Modify: `pkg/aws/cloudfront/types.go` — remove `ScanOptions` (lines 4-7) and `ScanResult` (lines 10-13). Preserve all other types (`Finding`, `DistributionInfo`, `OriginInfo`, `VulnerableDistribution`, `Route53Record`, `BucketExistence`, constants).
- Modify: `pkg/aws/cloudfront/buckets.go` — remove `findVulnerableDistributions` (lines 98-107), which was only called from `scan.go:45` and is now dead code. The per-distribution function `checkDistributionOrigins` (lines 65-94) is still used by the Checker.

- [ ] **Step 1: Verify no remaining references to `Scan`, `ScanOptions`, `ScanResult`, or `findVulnerableDistributions`**

Run: `grep -rn 'cloudfront\.Scan\|ScanOptions\|ScanResult\|findVulnerableDistributions' pkg/ test/ --include='*.go'`
Expected: only hits in `scan.go` itself, `types.go`, and `buckets.go` — no references from module code or tests

- [ ] **Step 2: Remove `ScanOptions` and `ScanResult` from `types.go`**

In `pkg/aws/cloudfront/types.go`, remove lines 3-13:
```go
// Remove these:
// ScanOptions configures the CloudFront S3 takeover scan.
type ScanOptions struct {
	Profile    string
	ProfileDir string
}

// ScanResult contains the findings from a CloudFront S3 takeover scan.
type ScanResult struct {
	Findings  []Finding
	AccountID string
}
```

Leave everything from `Finding` onward intact.

- [ ] **Step 3: Remove `findVulnerableDistributions` from `buckets.go`**

In `pkg/aws/cloudfront/buckets.go`, remove lines 96-107:
```go
// Remove this function:
// findVulnerableDistributions iterates over distributions, checks each S3 origin's
// bucket, and returns VulnerableDistribution entries for any missing buckets.
func findVulnerableDistributions(ctx context.Context, client S3API, distributions []DistributionInfo) []VulnerableDistribution {
	var result []VulnerableDistribution
	for _, dist := range distributions {
		vulnerable := checkDistributionOrigins(ctx, client, dist)
		result = append(result, vulnerable...)
	}
	return result
}
```

- [ ] **Step 4: Delete `scan.go`**

Run: `rm pkg/aws/cloudfront/scan.go`

- [ ] **Step 5: Verify compilation**

Run: `go build ./pkg/aws/cloudfront/... ./pkg/modules/aws/recon/...`
Expected: clean compile

- [ ] **Step 6: Run unit tests**

Run: `go test ./pkg/aws/cloudfront/... -v -count=1`
Expected: all existing tests pass (they don't depend on scan.go or the removed functions)

- [ ] **Step 7: Commit**

```bash
git add -u pkg/aws/cloudfront/scan.go pkg/aws/cloudfront/types.go pkg/aws/cloudfront/buckets.go
git commit -m "refactor(cloudfront): remove monolithic Scan function and dead code"
```

---

### Task 5: Update integration test

**Files:**
- Modify: `test/integration/aws/recon/cloudfront_s3_takeover_test.go`

The test already uses `testutil.RunAndCollect` with `plugin.Config{Args: map[string]any{}}`. Since the module now embeds `AWSCommonRecon`, `PostBind` will resolve regions from the default `"all"` and set concurrency to `5`. The test doesn't need to change behavior — it just needs to work with the new config shape.

The only functional change: verify the test still compiles and the module is correctly registered with the new config.

- [ ] **Step 1: Verify the integration test compiles**

Run: `go build ./test/integration/aws/recon/...` (won't run — needs `integration` build tag — but will check compilation)

Actually, since it has `//go:build integration`, check via vet:
Run: `go vet -tags=integration ./test/integration/aws/recon/...`
Expected: clean

- [ ] **Step 2: Run unit tests across all changed packages**

Run: `go test ./pkg/aws/cloudfront/... ./pkg/modules/aws/recon/... -v -count=1`
Expected: all pass

- [ ] **Step 3: Run go vet across all changed packages**

Run: `go vet ./pkg/aws/cloudfront/... ./pkg/modules/aws/recon/...`
Expected: clean

- [ ] **Step 4: Commit (if any changes were needed)**

Only if the integration test required modification. Otherwise skip.

---

### Task 6: Final verification

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: clean compile

- [ ] **Step 2: Full vet**

Run: `go vet ./...`
Expected: clean

- [ ] **Step 3: All unit tests**

Run: `go test ./... -count=1`
Expected: all pass

- [ ] **Step 4: Verify the CLI registers the module with new params**

Run: `go run . aws recon cloudfront-s3-takeover --help`
Expected: output shows `--resource-arn`, `--resource-type`, `--regions`, `--concurrency` flags (inherited from `AWSCommonRecon`)
