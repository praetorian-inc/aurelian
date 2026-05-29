package enumeration

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

var errFallbackToCloudControl = errors.New("fallback to cloud control")

// SkippedOp captures a single skipped (region, service) operation so the
// operator can see, after the run, which AWS calls were denied or unsupported
// without losing them in the noise.
type SkippedOp struct {
	Region    string // AWS region (or "global" for IAM and other non-regional services)
	Service   string // short service name, e.g. "amplify", "ec2", "iam"
	Operation string // AWS API operation, e.g. "ListApps", "DescribeImages"
	ErrorCode string // smithy code or "RegionUnsupported" / "Unknown"
	Detail    string // truncated raw error string (<= 500 chars)
}

const maxDetailLen = 500

// SkipReport is a thread-safe aggregator for SkippedOp records emitted from
// multiple goroutines during cross-region enumeration.
type SkipReport struct {
	mu  sync.Mutex
	ops []SkippedOp
}

// NewSkipReport returns an empty SkipReport ready for concurrent use.
func NewSkipReport() *SkipReport {
	return &SkipReport{}
}

// Record appends a SkippedOp to the report. The Detail field is truncated to
// at most 500 characters before storage.
func (r *SkipReport) Record(op SkippedOp) {
	if len(op.Detail) > maxDetailLen {
		op.Detail = op.Detail[:maxDetailLen]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
}

// Snapshot returns a copy of the current set of recorded ops, safe for use
// without holding the lock.
func (r *SkipReport) Snapshot() []SkippedOp {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]SkippedOp, len(r.ops))
	copy(cp, r.ops)
	return cp
}

// Len returns the number of recorded skips.
func (r *SkipReport) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ops)
}

// Summary renders a human-readable, deterministic summary grouped by
// "<service> <operation>" with all affected regions and the dominant error
// code per group. Returns an empty string if no ops were recorded.
func (r *SkipReport) Summary() string {
	ops := r.Snapshot()
	if len(ops) == 0 {
		return ""
	}

	type groupKey struct {
		service   string
		operation string
	}
	type groupVal struct {
		regions map[string]struct{}
		codes   map[string]int
	}

	groups := make(map[groupKey]*groupVal)
	for _, op := range ops {
		k := groupKey{service: op.Service, operation: op.Operation}
		g, ok := groups[k]
		if !ok {
			g = &groupVal{
				regions: make(map[string]struct{}),
				codes:   make(map[string]int),
			}
			groups[k] = g
		}
		g.regions[op.Region] = struct{}{}
		g.codes[op.ErrorCode]++
	}

	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		return keys[i].operation < keys[j].operation
	})

	allRegions := make(map[string]struct{})
	for _, g := range groups {
		for region := range g.regions {
			allRegions[region] = struct{}{}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "skipped %d operations across %d regions:\n", len(ops), len(allRegions))
	for _, k := range keys {
		g := groups[k]

		regions := make([]string, 0, len(g.regions))
		for reg := range g.regions {
			regions = append(regions, reg)
		}
		sort.Strings(regions)

		code := dominantCode(g.codes)

		fmt.Fprintf(&b, "  %s %s: %s [%s]\n", k.service, k.operation, strings.Join(regions, ", "), code)
	}
	return strings.TrimRight(b.String(), "\n")
}

// dominantCode returns the code with the highest count; ties broken
// alphabetically to keep output stable.
func dominantCode(counts map[string]int) string {
	best := ""
	bestN := -1
	for code, n := range counts {
		if n > bestN || (n == bestN && code < best) {
			best = code
			bestN = n
		}
	}
	return best
}

// LogSummary logs the skip report summary if any operations were skipped.
func (r *SkipReport) LogSummary() {
	s := r.Summary()
	if s == "" {
		return
	}
	slog.Warn(s)
}

// ResourceEnumerator enumerates AWS resources of a specific type.
type ResourceEnumerator interface {
	// ResourceType returns the CloudControl type string, e.g. "AWS::S3::Bucket".
	ResourceType() string

	// EnumerateAll enumerates all resources of this type across configured regions.
	EnumerateAll(out *pipeline.P[output.AWSResource]) error

	// EnumerateByARN fetches a single resource by ARN.
	EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error
}

// Enumerator dispatches resource enumeration to registered ResourceEnumerators,
// falling back to CloudControlEnumerator for unregistered types.
type Enumerator struct {
	enumerators map[string]ResourceEnumerator
	cc          *CloudControlEnumerator
	Skipped     SkipReport
}

// NewEnumerator creates an Enumerator with CloudControl fallback and registers
// all built-in resource-specific enumerators.
func NewEnumerator(opts plugin.AWSCommonRecon) *Enumerator {
	provider := NewAWSConfigProvider(opts)
	cc := NewCloudControlEnumeratorWithProvider(opts, provider)
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          cc,
	}
	// Register built-in enumerators here as they are implemented.
	e.Register(NewAmplifyAppEnumerator(opts, provider))
	e.Register(NewS3Enumerator(opts, provider))

	iamEnum := NewIAMEnumerator(opts, provider)
	e.Register(iamEnum.RoleEnumerator())
	e.Register(iamEnum.PolicyEnumerator())
	e.Register(iamEnum.UserEnumerator())

	e.Register(NewEC2ImageEnumerator(opts, provider))
	e.Register(NewSSMDocumentEnumerator(opts, provider))

	return e
}

// Register adds a ResourceEnumerator to the registry.
func (e *Enumerator) Register(l ResourceEnumerator) {
	e.enumerators[l.ResourceType()] = l
}

// List routes an identifier (ARN or resource type) to the appropriate enumerator.
// This has the same signature as CloudControlEnumerator.List for drop-in replacement.
// Skippable errors (access denied, unsupported type, region unavailable) are
// recorded in the SkipReport and swallowed so the pipeline continues. Non-skippable
// errors propagate so the caller sees real failures.
func (e *Enumerator) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		if err := e.listByARN(parsed, identifier, out); err != nil {
			return e.handleListError(err, identifier)
		}
		return nil
	}

	if strings.HasPrefix(identifier, "AWS::") {
		if err := e.listByType(identifier, out); err != nil {
			return e.handleListError(err, identifier)
		}
		return nil
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

// handleListError classifies err: skippable errors are recorded and nil is
// returned so the pipeline continues; everything else is returned as-is.
func (e *Enumerator) handleListError(err error, identifier string) error {
	if IsSkippableAWSError(err) {
		code := SkipReason(err)
		slog.Warn("skipping enumeration", "identifier", identifier, "code", code, "error", err)
		detail := err.Error()
		if len(detail) > maxDetailLen {
			detail = detail[:maxDetailLen]
		}
		e.Skipped.Record(SkippedOp{
			Service:   identifier,
			Operation: "List",
			ErrorCode: code,
			Detail:    detail,
		})
		return nil
	}
	return err
}

func (e *Enumerator) listByARN(parsed awsaarn.ARN, rawARN string, out *pipeline.P[output.AWSResource]) error {
	resourceType, ok := types.ResolveResourceType(parsed.Service, parsed.Resource)
	if !ok {
		return e.cc.EnumerateByARN(rawARN, out)
	}

	if enum, ok := e.enumerators[resourceType]; ok {
		err := enum.EnumerateByARN(rawARN, out)
		if errors.Is(err, errFallbackToCloudControl) {
			return e.cc.EnumerateByARN(rawARN, out)
		}
		return err
	}

	return e.cc.EnumerateByARN(rawARN, out)
}

func (e *Enumerator) listByType(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if enum, ok := e.enumerators[resourceType]; ok {
		return enum.EnumerateAll(out)
	}

	return e.cc.EnumerateByType(resourceType, out)
}
