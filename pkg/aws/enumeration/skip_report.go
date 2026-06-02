package enumeration

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// SkippedOp captures a single skipped (region, service) operation so the
// operator can see, after the run, which AWS calls were denied or unsupported
// without losing them in the noise.
type SkippedOp struct {
	Region    string `json:"region"`     // AWS region (or "global" for IAM and other non-regional services)
	Service   string `json:"service"`    // short service name, e.g. "amplify", "ec2", "iam"
	Operation string `json:"operation"`  // AWS API operation, e.g. "ListApps", "DescribeImages"
	ErrorCode string `json:"error_code"` // smithy code or "RegionUnsupported" / "Unknown"
	Detail    string `json:"detail"`     // truncated raw error string (<= 500 chars)
}

const maxDetailLen = 500

// maxInlineRegions is the threshold above which Summary() collapses
// region lists to a count instead of listing each one.
const maxInlineRegions = 5

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

// Summary renders a compact, deterministic summary grouped by
// "<service> <operation>". Region lists exceeding 5 entries are collapsed
// to a count. All distinct error codes per group are shown with counts.
// Returns an empty string if no ops were recorded.
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

		regionPart := formatRegions(g.regions)
		codePart := formatCodes(g.codes)

		fmt.Fprintf(&b, "  %s %s: %s %s\n", k.service, k.operation, regionPart, codePart)
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatRegions returns a compact region string: lists up to maxInlineRegions
// individually, otherwise collapses to "N regions".
func formatRegions(regions map[string]struct{}) string {
	if len(regions) > maxInlineRegions {
		return fmt.Sprintf("%d regions", len(regions))
	}
	sorted := make([]string, 0, len(regions))
	for r := range regions {
		sorted = append(sorted, r)
	}
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}

// formatCodes returns all distinct error codes with counts, sorted
// alphabetically. Example: "[AccessDeniedException×14, OptInRequired×3]"
func formatCodes(codes map[string]int) string {
	type codeCount struct {
		code  string
		count int
	}
	sorted := make([]codeCount, 0, len(codes))
	for c, n := range codes {
		sorted = append(sorted, codeCount{c, n})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].code < sorted[j].code
	})

	parts := make([]string, 0, len(sorted))
	for _, cc := range sorted {
		if cc.count == 1 {
			parts = append(parts, cc.code)
		} else {
			parts = append(parts, fmt.Sprintf("%s×%d", cc.code, cc.count))
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// LogSummary logs the skip report summary if any operations were skipped.
func (r *SkipReport) LogSummary() {
	s := r.Summary()
	if s == "" {
		return
	}
	slog.Warn(s)
}

// WriteDetailFile writes the full skip report as JSON to
// <dir>/enumeration-skips.json. This file contains every SkippedOp with all
// fields for post-run analysis and debugging. Returns nil if no ops were
// recorded (no file is created).
func (r *SkipReport) WriteDetailFile(dir string) error {
	ops := r.Snapshot()
	if len(ops) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	path := filepath.Join(dir, "enumeration-skips.json")
	data, err := json.MarshalIndent(ops, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal skip report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	slog.Debug("skip report written", "path", path, "count", len(ops))
	return nil
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
