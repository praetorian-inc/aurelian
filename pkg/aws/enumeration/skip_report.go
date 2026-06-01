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

// Record appends a single SkippedOp to the report. Prefer RecordBatch in hot
// paths to reduce lock acquisitions.
func (r *SkipReport) Record(op SkippedOp) {
	if len(op.Detail) > maxDetailLen {
		op.Detail = op.Detail[:maxDetailLen]
	}
	r.mu.Lock()
	r.ops = append(r.ops, op)
	r.mu.Unlock()
}

// RecordBatch appends multiple SkippedOps in a single lock acquisition.
// Callers should accumulate ops locally (lock-free) during a region loop and
// flush once when the loop completes.
func (r *SkipReport) RecordBatch(ops []SkippedOp) {
	if len(ops) == 0 {
		return
	}
	for i := range ops {
		if len(ops[i].Detail) > maxDetailLen {
			ops[i].Detail = ops[i].Detail[:maxDetailLen]
		}
	}
	r.mu.Lock()
	r.ops = append(r.ops, ops...)
	r.mu.Unlock()
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

// ClassifySkippable checks whether err is a skippable AWS error. If so, it
// logs at Debug level (individual skips are noisy; the aggregated summary
// logged by LogSummary at Warn level is the operator-facing output) and
// returns a *SkippedOp suitable for local accumulation.
// Returns nil when the error is not skippable (caller must propagate it).
//
// This function acquires no locks — callers collect the returned ops into a
// local slice and flush via RecordBatch once per region, keeping the hot path
// lock-free.
func ClassifySkippable(err error, service, operation, region string) *SkippedOp {
	if !IsSkippableAWSError(err) {
		return nil
	}
	code := SkipReason(err)
	slog.Debug("skipping "+service+" "+operation, "region", region, "code", code, "error", err)
	detail := err.Error()
	if len(detail) > maxDetailLen {
		detail = detail[:maxDetailLen]
	}
	return &SkippedOp{
		Region:    region,
		Service:   service,
		Operation: operation,
		ErrorCode: code,
		Detail:    detail,
	}
}
