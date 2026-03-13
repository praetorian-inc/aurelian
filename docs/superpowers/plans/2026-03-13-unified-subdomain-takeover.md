# Unified Subdomain Takeover Module Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate three separate subdomain takeover PRs (#53 EB, #54 EIP, #55 NS) into a single `subdomain-takeover` module using the extraction registry pattern from `pkg/aws/extraction/`.

**Architecture:** A single `subdomain-takeover` module enumerates Route53 records from public hosted zones, then dispatches each record to registered checkers via a registry (mirroring `extraction/registry.go`). Each checker validates a specific takeover type (EB CNAME, EIP A-record, NS delegation) and emits `output.AurelianRisk` findings into the pipeline. The module uses `pipeline.Pipe` for streaming with concurrency control.

**Tech Stack:** Go 1.25+, AWS SDK v2 (Route53, ElasticBeanstalk, EC2), `pipeline.P[T]`, `ratelimit.CrossRegionActor`, `errgroup`

**Original contributors:** All original work by Connor Cushing <connor.cushing@praetorian.com> from PRs #53, #54, #55. This plan restructures that work into the main branch architecture.

---

## File Structure

```
pkg/aws/dnstakeover/              # New component package
├── registry.go                   # checkerFunc type + mustRegister + getCheckers
├── checker.go                    # DNSTakeoverChecker component with .Check() pipeline method
├── route53.go                    # Shared Route53 zone + record enumeration
├── types.go                      # Route53Record, CheckContext, risk builder helpers
├── check_eb.go                   # EB CNAME takeover checker (from PR #53)
├── check_eip.go                  # EIP dangling A record checker (from PR #54)
└── check_ns.go                   # NS delegation takeover checker (from PR #55)

pkg/modules/aws/recon/
└── subdomain_takeover.go         # Thin module wiring (like find_secrets.go)

docs/
├── aurelian_aws_recon.md                      # Modify: add subdomain-takeover entry
└── aurelian_aws_recon_subdomain-takeover.md   # New: CLI docs
```

**Files removed** (replaced by unified structure):
- `pkg/aws/ebtakeover/` (entire directory)
- `pkg/aws/eiptakeover/` (entire directory)
- `pkg/aws/nstakeover/` (entire directory)
- `pkg/modules/aws/recon/eb_subdomain_takeover.go`
- `pkg/modules/aws/recon/eip_dangling_takeover.go`
- `pkg/modules/aws/recon/ns_delegation_takeover.go`

---

## Chunk 1: Branch Setup and Route53 Enumeration Component

### Task 0: Create branch and bring in original commits

**Purpose:** Create a clean branch off main that includes the original contributors' commits for git attribution, then restructure on top.

- [ ] **Step 1: Fetch all remote branches**

```bash
git fetch origin
```

- [ ] **Step 2: Create the unified branch from main**

```bash
git checkout -b cc/subdomain-takeover origin/main
```

- [ ] **Step 3: Cherry-pick original feature commits (not docs auto-gen commits)**

Cherry-pick the original contributor commits to preserve authorship. These will be restructured in subsequent tasks, but git history retains credit.

```bash
git cherry-pick 26e5cfa2656109121bf3345a5490c1691681ba94  # EB feature
git cherry-pick d02c480561c8ce5f09fdf2653eb24441dab53870  # EIP feature
git cherry-pick e69008361e89df8acfb45ce0a084d89f81c939f1  # NS feature
git cherry-pick 4afaa79eb6b7227ca52e61bdcca524be95ab8e7d  # NS bugfix
```

Resolve any merge conflicts by accepting the incoming changes — we're preserving authorship, not final code. The code will be rewritten in subsequent tasks.

- [ ] **Step 4: Verify branch state**

```bash
git log --oneline -10
go build ./...
```

Expected: branch has 4 cherry-picked commits on top of main. Build may have issues from merge conflicts — that's fine, we're rewriting.

- [ ] **Step 5: Commit merge resolution if needed**

If cherry-picks had conflicts:
```bash
git add .
git commit -m "resolve cherry-pick conflicts from PR #53, #54, #55 consolidation"
```

---

### Task 1: Route53 enumeration types

**Files:**
- Create: `pkg/aws/dnstakeover/types.go`

- [ ] **Step 1: Create the types file**

```go
package dnstakeover

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Route53Record represents a single DNS record from a public hosted zone.
type Route53Record struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	Type       string   // "CNAME", "A", "NS", etc.
	Values     []string // CNAME targets, IPs, or nameservers
	IsAlias    bool
}

// CheckContext holds shared state for checker functions.
type CheckContext struct {
	Opts      plugin.AWSCommonRecon
	AccountID string
}

// NewTakeoverRisk builds an AurelianRisk for a subdomain takeover finding.
func NewTakeoverRisk(name string, severity output.RiskSeverity, rec Route53Record, accountID string, context map[string]any) output.AurelianRisk {
	context["account_id"] = accountID
	context["zone_id"] = rec.ZoneID
	context["zone_name"] = rec.ZoneName
	context["record_name"] = rec.RecordName
	context["record_type"] = rec.Type
	context["record_values"] = rec.Values

	ctxBytes, _ := json.Marshal(context)

	resourceID := fmt.Sprintf("arn:aws:route53:::hostedzone/%s/recordset/%s/%s",
		rec.ZoneID, rec.RecordName, rec.Type)

	return output.AurelianRisk{
		Name:               name,
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("%s:%s:%s", name, rec.ZoneID, rec.RecordName),
		Context:            ctxBytes,
	}
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/types.go
git commit -m "feat(dnstakeover): add Route53 record types and risk builder"
```

---

### Task 2: Route53 enumeration component

**Files:**
- Create: `pkg/aws/dnstakeover/route53.go`

This is the shared Route53 enumeration — the deduplicated code that all three PRs had separately.

- [ ] **Step 1: Create the Route53 enumerator**

```go
package dnstakeover

import (
	"context"
	"log/slog"
	"strings"

	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Route53Enumerator lists all DNS records from public hosted zones.
type Route53Enumerator struct {
	opts plugin.AWSCommonRecon
}

// NewRoute53Enumerator creates a Route53 record enumerator.
func NewRoute53Enumerator(opts plugin.AWSCommonRecon) *Route53Enumerator {
	return &Route53Enumerator{opts: opts}
}

// EnumerateAll is a pipeline-compatible method that lists all records from
// all public hosted zones. It accepts a dummy string input to satisfy
// pipeline.Pipe when used with pipeline.From("route53").
func (e *Route53Enumerator) EnumerateAll(_ string, out *pipeline.P[Route53Record]) error {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1", // Route53 is global
		Profile:    e.opts.Profile,
		ProfileDir: e.opts.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create route53 config: %w", err)
	}

	client := route53.NewFromConfig(cfg)
	return e.enumerateZones(client, out)
}

func (e *Route53Enumerator) enumerateZones(client *route53.Client, out *pipeline.P[Route53Record]) error {
	var marker *string
	for {
		input := &route53.ListHostedZonesInput{}
		if marker != nil {
			input.Marker = marker
		}

		resp, err := client.ListHostedZones(context.Background(), input)
		if err != nil {
			return fmt.Errorf("list hosted zones: %w", err)
		}

		for _, hz := range resp.HostedZones {
			if hz.Config != nil && hz.Config.PrivateZone {
				continue
			}

			zoneID := strings.TrimPrefix(aws.ToString(hz.Id), "/hostedzone/")
			zoneName := strings.TrimSuffix(aws.ToString(hz.Name), ".")

			if err := e.enumerateRecords(client, zoneID, zoneName, out); err != nil {
				slog.Warn("failed to enumerate zone records", "zone_id", zoneID, "zone_name", zoneName, "error", err)
			}
		}

		if !resp.IsTruncated {
			break
		}
		marker = resp.NextMarker
	}

	return nil
}

func (e *Route53Enumerator) enumerateRecords(client *route53.Client, zoneID, zoneName string, out *pipeline.P[Route53Record]) error {
	var startName *string
	var startType r53types.RRType

	for {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(zoneID),
		}
		if startName != nil {
			input.StartRecordName = startName
			input.StartRecordType = startType
		}

		resp, err := client.ListResourceRecordSets(context.Background(), input)
		if err != nil {
			return fmt.Errorf("list record sets for zone %s: %w", zoneID, err)
		}

		for _, rrs := range resp.ResourceRecordSets {
			var values []string
			for _, rr := range rrs.ResourceRecords {
				if rr.Value != nil {
					values = append(values, aws.ToString(rr.Value))
				}
			}

			out.Send(Route53Record{
				ZoneID:     zoneID,
				ZoneName:   zoneName,
				RecordName: strings.TrimSuffix(aws.ToString(rrs.Name), "."),
				Type:       string(rrs.Type),
				Values:     values,
				IsAlias:    rrs.AliasTarget != nil,
			})
		}

		if !resp.IsTruncated {
			break
		}
		startName = resp.NextRecordName
		startType = resp.NextRecordType
	}

	return nil
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/route53.go
git commit -m "feat(dnstakeover): add shared Route53 record enumerator component"
```

---

### Task 3: Checker registry

**Files:**
- Create: `pkg/aws/dnstakeover/registry.go`

This mirrors `pkg/aws/extraction/registry.go` exactly.

- [ ] **Step 1: Create the registry**

```go
package dnstakeover

import (
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// checkerFunc is the signature for per-record-type takeover check functions.
// Mirrors extractorFunc from pkg/aws/extraction/registry.go.
type checkerFunc func(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error

type registeredChecker struct {
	Name       string
	RecordType string // "CNAME", "A", "NS"
	Fn         checkerFunc
}

var checkersByRecordType = map[string][]registeredChecker{}

func mustRegister(recordType, name string, fn checkerFunc) {
	if recordType == "" {
		panic("checker record type cannot be empty")
	}
	if name == "" {
		panic("checker name cannot be empty")
	}
	if fn == nil {
		panic("checker function cannot be nil")
	}

	existing := checkersByRecordType[recordType]
	for _, item := range existing {
		if item.Name == name {
			panic("checker already registered: " + recordType + "/" + name)
		}
	}
	checkersByRecordType[recordType] = append(existing, registeredChecker{
		Name:       name,
		RecordType: recordType,
		Fn:         fn,
	})
}

func getCheckers(recordType string) []registeredChecker {
	return checkersByRecordType[recordType]
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/registry.go
git commit -m "feat(dnstakeover): add checker registry mirroring extraction pattern"
```

---

### Task 4: DNSTakeoverChecker component

**Files:**
- Create: `pkg/aws/dnstakeover/checker.go`

This mirrors `pkg/aws/extraction/extractor.go` — the dispatcher that connects the registry to the pipeline.

- [ ] **Step 1: Create the checker component**

```go
package dnstakeover

import (
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DNSTakeoverChecker dispatches Route53 records to registered checkers by record type.
// Mirrors AWSExtractor from pkg/aws/extraction/extractor.go.
type DNSTakeoverChecker struct {
	ctx CheckContext
}

// NewDNSTakeoverChecker creates a checker with shared AWS options.
func NewDNSTakeoverChecker(opts plugin.AWSCommonRecon) (*DNSTakeoverChecker, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create aws config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve account id: %w", err)
	}

	return &DNSTakeoverChecker{
		ctx: CheckContext{
			Opts:      opts,
			AccountID: accountID,
		},
	}, nil
}

// Check is the pipeline-compatible method that dispatches to registered checkers.
func (c *DNSTakeoverChecker) Check(rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	checkers := getCheckers(rec.Type)
	if len(checkers) == 0 {
		return nil // no checkers registered for this record type — skip silently
	}

	for _, chk := range checkers {
		if err := chk.Fn(c.ctx, rec, out); err != nil {
			slog.Warn("takeover checker failed",
				"name", chk.Name,
				"record_type", rec.Type,
				"record", rec.RecordName,
				"error", err,
			)
		}
	}
	return nil
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/checker.go
git commit -m "feat(dnstakeover): add checker dispatcher component mirroring AWSExtractor"
```

---

## Chunk 2: Individual Takeover Checkers

### Task 5: Elastic Beanstalk CNAME checker

**Files:**
- Create: `pkg/aws/dnstakeover/check_eb.go`

Port the EB validation logic from PR #53's `pkg/aws/ebtakeover/validate.go` and `types.go`.

- [ ] **Step 1: Create the EB checker**

```go
package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "eb-takeover", checkEB)
}

// ebCNAMEPattern matches Elastic Beanstalk CNAME targets.
// Captures: [1] prefix, [2] region
var ebCNAMEPattern = regexp.MustCompile(`^([a-zA-Z0-9-]+)\.((?:[a-z]{2}(?:-[a-z]+)+-\d+))\.elasticbeanstalk\.com\.?$`)

func checkEB(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		m := ebCNAMEPattern.FindStringSubmatch(val)
		if m == nil {
			continue
		}

		prefix, region := m[1], m[2]

		available, err := checkEBDNSAvailability(ctx, prefix, region)
		if err != nil {
			slog.Warn("eb dns availability check failed",
				"record", rec.RecordName,
				"prefix", prefix,
				"region", region,
				"error", err,
			)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"eb-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			ctx.AccountID,
			map[string]any{
				"cname_target": val,
				"eb_prefix":    prefix,
				"eb_region":    region,
				"description": fmt.Sprintf(
					"Route53 CNAME %q points to unclaimed EB prefix %q in %s. "+
						"An attacker can register this prefix and serve arbitrary content.",
					rec.RecordName, prefix, region,
				),
				"recommendation": "Remove the stale CNAME record or recreate the EB environment with the original prefix.",
				"references": []string{
					"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
					"https://hackerone.com/reports/473888",
				},
			},
		))
	}

	return nil
}

func checkEBDNSAvailability(ctx CheckContext, prefix, region string) (bool, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    ctx.Opts.Profile,
		ProfileDir: ctx.Opts.ProfileDir,
	})
	if err != nil {
		return false, fmt.Errorf("create eb config for region %s: %w", region, err)
	}

	client := elasticbeanstalk.NewFromConfig(cfg)
	resp, err := client.CheckDNSAvailability(context.Background(), &elasticbeanstalk.CheckDNSAvailabilityInput{
		CNAMEPrefix: aws.String(prefix),
	})
	if err != nil {
		return false, err
	}

	if resp.Available == nil {
		return false, nil
	}
	return *resp.Available, nil
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/check_eb.go
git commit -m "feat(dnstakeover): add EB CNAME takeover checker

Ported from PR #53 by Connor Cushing."
```

---

### Task 6: EIP dangling A record checker

**Files:**
- Create: `pkg/aws/dnstakeover/check_eip.go`

Port the EIP validation logic from PR #54's `pkg/aws/eiptakeover/`. This checker needs to fetch AWS IP ranges and allocated EIPs upfront (collect-then-check), so it uses a `sync.Once` for lazy initialization.

- [ ] **Step 1: Create the EIP checker**

```go
package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	mustRegister("A", "eip-dangling", checkEIP)
}

const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// eipState holds lazily-initialized data shared across all A record checks.
var (
	eipOnce  sync.Once
	eipState struct {
		ranges       []parsedPrefix
		allocatedIPs map[string]bool
		err          error
	}
)

type ipPrefixEntry struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type parsedPrefix struct {
	network *net.IPNet
	region  string
	service string
}

func checkEIP(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	if rec.IsAlias {
		return nil // alias A records point to AWS endpoints, not raw IPs
	}

	eipOnce.Do(func() {
		eipState.ranges, eipState.allocatedIPs, eipState.err = initEIPState(ctx)
	})
	if eipState.err != nil {
		return fmt.Errorf("eip state initialization failed: %w", eipState.err)
	}

	for _, ip := range rec.Values {
		awsRegion, awsService, inAWS := containsIP(eipState.ranges, ip)
		if !inAWS {
			continue
		}
		if eipState.allocatedIPs[ip] {
			continue
		}

		out.Send(NewTakeoverRisk(
			"eip-dangling-a-record",
			output.RiskSeverityMedium,
			rec,
			ctx.AccountID,
			map[string]any{
				"dangling_ip":  ip,
				"aws_region":   awsRegion,
				"aws_service":  awsService,
				"description": fmt.Sprintf(
					"Route53 A record %q points to %s which is in AWS IP space (%s/%s) "+
						"but is not allocated as an EIP in this account.",
					rec.RecordName, ip, awsService, awsRegion,
				),
				"recommendation": "Remove the stale A record or re-allocate the Elastic IP.",
				"references": []string{
					"https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains",
					"https://kmsec.uk/blog/passive-takeover/",
				},
			},
		))
	}

	return nil
}

func initEIPState(ctx CheckContext) ([]parsedPrefix, map[string]bool, error) {
	slog.Info("eip checker: fetching aws ip ranges")
	ranges, err := fetchAWSIPRanges()
	if err != nil {
		return nil, nil, err
	}
	slog.Info("eip checker: loaded aws ip prefixes", "count", len(ranges))

	slog.Info("eip checker: enumerating allocated eips across regions")
	allocated, err := fetchAllocatedEIPs(ctx)
	if err != nil {
		return nil, nil, err
	}
	slog.Info("eip checker: found allocated eips", "count", len(allocated))

	return ranges, allocated, nil
}

func fetchAWSIPRanges() ([]parsedPrefix, error) {
	resp, err := http.Get(awsIPRangesURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch aws ip ranges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch aws ip ranges: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read aws ip ranges: %w", err)
	}

	var raw struct {
		Prefixes []ipPrefixEntry `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse aws ip ranges: %w", err)
	}

	var prefixes []parsedPrefix
	for _, p := range raw.Prefixes {
		if p.IPPrefix == "" {
			continue
		}
		_, network, err := net.ParseCIDR(p.IPPrefix)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, parsedPrefix{
			network: network,
			region:  p.Region,
			service: p.Service,
		})
	}

	return prefixes, nil
}

func containsIP(prefixes []parsedPrefix, ip string) (region, service string, ok bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", false
	}
	for _, p := range prefixes {
		if p.network.Contains(parsed) {
			return p.region, p.service, true
		}
	}
	return "", "", false
}

func fetchAllocatedEIPs(ctx CheckContext) (map[string]bool, error) {
	allocated := make(map[string]bool)
	var mu sync.Mutex

	actor := ratelimit.NewCrossRegionActor(ctx.Opts.Concurrency)
	err := actor.ActInRegions(ctx.Opts.Regions, func(region string) error {
		cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    ctx.Opts.Profile,
			ProfileDir: ctx.Opts.ProfileDir,
		})
		if err != nil {
			return fmt.Errorf("region %s: %w", region, err)
		}

		client := ec2.NewFromConfig(cfg)
		resp, err := client.DescribeAddresses(context.Background(), &ec2.DescribeAddressesInput{})
		if err != nil {
			return fmt.Errorf("region %s describe addresses: %w", region, err)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, addr := range resp.Addresses {
			if addr.PublicIp != nil {
				allocated[aws.ToString(addr.PublicIp)] = true
			}
		}
		return nil
	})

	return allocated, err
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/check_eip.go
git commit -m "feat(dnstakeover): add EIP dangling A record checker

Ported from PR #54 by Connor Cushing."
```

---

### Task 7: NS delegation takeover checker

**Files:**
- Create: `pkg/aws/dnstakeover/check_ns.go`

Port the NS validation logic from PR #55's `pkg/aws/nstakeover/validate.go`. This checker queries delegated nameservers directly via `net.Resolver`.

- [ ] **Step 1: Create the NS checker**

```go
package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("NS", "ns-delegation", checkNS)
}

var nsRoute53Pattern = regexp.MustCompile(`(?i)^ns-\d+\.awsdns-\d+\.\w+`)

func checkNS(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	// Skip apex NS records — these are the zone's own nameservers, not delegations.
	if rec.RecordName == rec.ZoneName {
		return nil
	}

	// Collect only Route53-pattern nameservers.
	var route53NSes []string
	for _, ns := range rec.Values {
		ns = strings.TrimSuffix(ns, ".")
		if nsRoute53Pattern.MatchString(ns) {
			route53NSes = append(route53NSes, ns)
		}
	}

	if len(route53NSes) == 0 {
		return nil
	}

	queryErr := validateNSDelegation(rec.RecordName, route53NSes[0])
	if queryErr == "" {
		return nil // zone is alive
	}

	slog.Info("dangling ns delegation detected",
		"record", rec.RecordName,
		"zone", rec.ZoneName,
		"nameserver", route53NSes[0],
		"error_type", queryErr,
	)

	out.Send(NewTakeoverRisk(
		"ns-delegation-takeover",
		output.RiskSeverityHigh,
		rec,
		ctx.AccountID,
		map[string]any{
			"nameservers": route53NSes,
			"query_error": queryErr,
			"description": fmt.Sprintf(
				"Route53 NS delegation %q delegates to Route53 nameservers (%s) "+
					"but the hosted zone no longer exists (DNS: %s). An attacker can "+
					"exploit the Form3 bypass to gain full DNS control.",
				rec.RecordName, strings.Join(route53NSes, ", "), queryErr,
			),
			"recommendation": "Remove the stale NS delegation record from zone " + rec.ZoneName + ".",
			"references": []string{
				"https://www.form3.tech/blog/engineering/dangling-danger",
				"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
				"https://0xpatrik.com/subdomain-takeover-ns/",
			},
		},
	))

	return nil
}

func validateNSDelegation(recordName, nameserver string) string {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "udp", nameserver+":53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := resolver.LookupNS(ctx, recordName)
	if err == nil {
		return "" // zone exists
	}

	dnsErr, ok := err.(*net.DNSError)
	if !ok || dnsErr.IsTimeout {
		return "" // transient — don't flag
	}

	return classifyDNSError(dnsErr)
}

func classifyDNSError(dnsErr *net.DNSError) string {
	if dnsErr.IsNotFound {
		return "NXDOMAIN"
	}

	errMsg := strings.ToUpper(dnsErr.Error())
	switch {
	case strings.Contains(errMsg, "SERVFAIL") || strings.Contains(errMsg, "SERVER FAILURE"):
		return "SERVFAIL"
	case strings.Contains(errMsg, "REFUSED"):
		return "REFUSED"
	case strings.Contains(errMsg, "SERVER MISBEHAVING"):
		return "REFUSED" // Go translates REFUSED to "server misbehaving"
	case strings.Contains(errMsg, "NXDOMAIN") || strings.Contains(errMsg, "NO SUCH HOST"):
		return "NXDOMAIN"
	default:
		return "" // unknown — don't flag
	}
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/aws/dnstakeover/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/aws/dnstakeover/check_ns.go
git commit -m "feat(dnstakeover): add NS delegation takeover checker

Ported from PR #55 by Connor Cushing."
```

---

## Chunk 3: Module, Cleanup, and Integration

### Task 8: Thin module wiring

**Files:**
- Create: `pkg/modules/aws/recon/subdomain_takeover.go`

This follows the same pattern as `find_secrets.go`: thin module that wires components into a pipeline.

- [ ] **Step 1: Create the module**

```go
package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/dnstakeover"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&SubdomainTakeoverModule{})
}

type SubdomainTakeoverConfig struct {
	plugin.AWSCommonRecon
}

type SubdomainTakeoverModule struct {
	SubdomainTakeoverConfig
}

func (m *SubdomainTakeoverModule) ID() string                { return "subdomain-takeover" }
func (m *SubdomainTakeoverModule) Name() string              { return "AWS Subdomain Takeover" }
func (m *SubdomainTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *SubdomainTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *SubdomainTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *SubdomainTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *SubdomainTakeoverModule) Parameters() any           { return &m.SubdomainTakeoverConfig }

func (m *SubdomainTakeoverModule) Description() string {
	return "Detects dangling DNS records in Route53 that are vulnerable to subdomain takeover. " +
		"Enumerates all records from public hosted zones and checks for: Elastic Beanstalk " +
		"CNAME hijacking, dangling Elastic IP A records, and orphaned NS delegations."
}

func (m *SubdomainTakeoverModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
		"https://www.form3.tech/blog/engineering/dangling-danger",
		"https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains",
	}
}

func (m *SubdomainTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Route53::HostedZone",
	}
}

func (m *SubdomainTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	checker, err := dnstakeover.NewDNSTakeoverChecker(m.AWSCommonRecon)
	if err != nil {
		return err
	}

	cfg.Info("enumerating Route53 records from public hosted zones")

	enumerator := dnstakeover.NewRoute53Enumerator(m.AWSCommonRecon)
	trigger := pipeline.From("route53")

	records := pipeline.New[dnstakeover.Route53Record]()
	pipeline.Pipe(trigger, enumerator.EnumerateAll, records, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("enumerating route53 records"),
	})

	pipeline.Pipe(records, checker.Check, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking for takeover"),
		Concurrency: m.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("subdomain takeover scan complete")
	return nil
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/modules/aws/recon/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/modules/aws/recon/subdomain_takeover.go
git commit -m "feat: add unified subdomain-takeover module

Single module using registry + pipeline pattern mirroring find-secrets.
Dispatches Route53 records to registered checkers (EB, EIP, NS)."
```

---

### Task 9: Remove old separate modules and packages

**Files:**
- Remove: `pkg/aws/ebtakeover/` (entire directory)
- Remove: `pkg/aws/eiptakeover/` (entire directory)
- Remove: `pkg/aws/nstakeover/` (entire directory)
- Remove: `pkg/modules/aws/recon/eb_subdomain_takeover.go`
- Remove: `pkg/modules/aws/recon/eip_dangling_takeover.go`
- Remove: `pkg/modules/aws/recon/ns_delegation_takeover.go`

- [ ] **Step 1: Remove old packages**

```bash
rm -rf pkg/aws/ebtakeover/ pkg/aws/eiptakeover/ pkg/aws/nstakeover/
rm -f pkg/modules/aws/recon/eb_subdomain_takeover.go
rm -f pkg/modules/aws/recon/eip_dangling_takeover.go
rm -f pkg/modules/aws/recon/ns_delegation_takeover.go
```

- [ ] **Step 2: Remove old docs**

```bash
rm -f docs/aurelian_aws_recon_eb-subdomain-takeover.md
rm -f docs/aurelian_aws_recon_eip-dangling-takeover.md
rm -f docs/aurelian_aws_recon_ns-delegation-takeover.md
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

Expected: PASS — no references to the old packages should remain.

- [ ] **Step 4: Run vet**

```bash
go vet ./...
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove old separate takeover modules

Replaced by unified subdomain-takeover module with registry pattern."
```

---

### Task 10: Update go.mod dependencies

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

Ensure the required SDK dependencies are present (Route53, ElasticBeanstalk are needed; EC2 already exists).

- [ ] **Step 1: Tidy modules**

```bash
go mod tidy
```

- [ ] **Step 2: Verify build**

```bash
go build ./...
go vet ./...
```

Expected: both PASS

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: tidy go.mod after subdomain-takeover consolidation"
```

---

### Task 11: Generate CLI docs

**Files:**
- Regenerate: `docs/` (via `gendoc` subcommand in `cmd/doc.go`)

- [ ] **Step 1: Regenerate CLI docs**

```bash
go run . gendoc
```

Expected: "Documentation generated in ./docs" — produces `docs/aurelian_aws_recon_subdomain-takeover.md` and removes the three old takeover doc files.

- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs: regenerate CLI docs for subdomain-takeover module"
```

---

### Task 12: Final verification

- [ ] **Step 1: Full build**

```bash
go build ./...
```

Expected: PASS

- [ ] **Step 2: Full vet**

```bash
go vet ./...
```

Expected: PASS

- [ ] **Step 3: Run existing tests**

```bash
go test ./... 2>&1 | tail -20
```

Expected: all existing tests PASS

- [ ] **Step 4: Verify the module registers correctly**

```bash
go run . aws recon subdomain-takeover --help
```

Expected: shows CLI help with `--profile`, `--regions`, `--concurrency` flags

- [ ] **Step 5: Review git log**

```bash
git log --oneline --graph origin/main..HEAD
```

Expected: clean linear history with original contributor commits at the base, then the restructuring commits on top.
