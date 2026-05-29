package enumeration

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

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

// RecordSkippable classifies err and, if it represents a non-fatal
// per-(region, service) failure, logs at Warn and records the skip. Returns
// true when the error was handled (skippable) and the caller should treat it
// as a soft success; false when err is fatal and the caller must propagate it.
//
// extraLogAttrs are appended to the standard Warn attributes ("region",
// "code", "error"); pass them as key/value pairs, e.g. "arn", resourceARN.
func (r *SkipReport) RecordSkippable(err error, service, operation, region string, extraLogAttrs ...any) bool {
	if !IsSkippableAWSError(err) {
		return false
	}
	code := SkipReason(err)
	attrs := append([]any{"region", region, "code", code, "error", err}, extraLogAttrs...)
	slog.Warn("skipping "+service+" "+operation, attrs...)
	r.Record(SkippedOp{
		Region:    region,
		Service:   service,
		Operation: operation,
		ErrorCode: code,
		Detail:    err.Error(),
	})
	return true
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
		for r := range g.regions {
			regions = append(regions, r)
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
