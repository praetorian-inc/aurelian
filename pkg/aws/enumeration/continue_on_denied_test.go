package enumeration

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LAB-2525: AWS recon must continue past SCP/AccessDenied/OptInRequired errors
// returned from a single (region, service) call. The enumerator pattern is:
//
//	if op := ClassifySkippable(err, service, operation, region); op != nil {
//	    skipped = append(skipped, *op)
//	    return nil   // <-- swallow so CrossRegionActor's errgroup doesn't cancel siblings
//	}
//	return err       // fatal -> propagate
//
// These tests simulate that decision point by driving CrossRegionActor with a
// fake per-region action that returns the AWS error shapes the enumerators see
// in production, then assert on the post-run state (errgroup result + SkipReport
// contents). This is the integration-style seam that proves the loop continues.

// regionErrPlan controls what error each region's fake action returns.
type regionErrPlan map[string]error

// runWithSkipHandling simulates the wrapper every real enumerator now performs:
// errors that pass IsSkippableAWSError are recorded into the SkipReport and
// converted to nil; everything else propagates.
func runWithSkipHandling(t *testing.T, regions []string, plan regionErrPlan, report *SkipReport) (int, error) {
	t.Helper()

	var invoked int64
	actor := ratelimit.NewCrossRegionActor(len(regions))
	err := actor.ActInRegions(regions, func(region string) error {
		atomic.AddInt64(&invoked, 1)
		regionErr, hasErr := plan[region]
		if !hasErr {
			return nil
		}
		if IsSkippableAWSError(regionErr) {
			report.Record(SkippedOp{
				Region:    region,
				Service:   "amplify",
				Operation: "ListApps",
				ErrorCode: SkipReason(regionErr),
				Detail:    regionErr.Error(),
			})
			return nil
		}
		return regionErr
	})
	return int(atomic.LoadInt64(&invoked)), err
}

// TP1: one region denied (AccessDeniedException), one region succeeds.
// Both region actions must be invoked, and ActInRegions must return nil so the
// caller (the recon module) keeps processing results from the surviving region.
func TestContinueOnDenied_AccessDenied_AcrossTwoRegions_LoopCompletes(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": &fakeAPIError{code: "AccessDeniedException", msg: "denied by SCP"},
		// "us-east-2" has no plan entry -> succeeds.
	}

	invoked, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)

	require.NoError(t, err, "errgroup should return nil when only skippable errors occurred")
	assert.Equal(t, 2, invoked, "both region actions must run; sibling must not be cancelled")
}

// TP2: the denied region records the (region, service, op, code) tuple. This
// is what surfaces in the operator-facing SkipReport.Summary().
func TestContinueOnDenied_AccessDenied_RecordsSkipTuple(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": &fakeAPIError{code: "AccessDeniedException", msg: "denied by SCP"},
	}

	_, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)
	require.NoError(t, err)

	require.Equal(t, 1, report.Len(), "exactly one region should have been recorded")
	snap := report.Snapshot()
	require.Len(t, snap, 1)
	got := snap[0]
	assert.Equal(t, "us-east-1", got.Region)
	assert.Equal(t, "amplify", got.Service)
	assert.Equal(t, "ListApps", got.Operation)
	assert.Equal(t, "AccessDeniedException", got.ErrorCode)
	assert.Contains(t, got.Detail, "denied by SCP")
}

// TP3: every skippable error code class is exercised together. All regions must
// complete; the SkipReport must hold all three distinct codes.
func TestContinueOnDenied_MultipleSkippableCodes_AllRegionsComplete(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1":      &fakeAPIError{code: "AccessDeniedException", msg: "scp deny"},
		"us-west-2":      &fakeAPIError{code: "OptInRequired", msg: "region not opted in"},
		"ap-northeast-3": errors.New("dial tcp: lookup amplify.ap-northeast-3.amazonaws.com: no such host"),
		"eu-west-1":      nil, // success
	}

	regions := []string{"us-east-1", "us-west-2", "ap-northeast-3", "eu-west-1"}
	invoked, err := runWithSkipHandling(t, regions, plan, report)

	require.NoError(t, err, "all errors were skippable, errgroup must return nil")
	assert.Equal(t, 4, invoked, "every region action must run")
	require.Equal(t, 3, report.Len(), "three regions recorded skips; one was a clean success")

	// Collect codes for assertion, order-independent.
	codes := make([]string, 0, 3)
	for _, op := range report.Snapshot() {
		codes = append(codes, op.ErrorCode)
	}
	sort.Strings(codes)
	assert.Equal(t, []string{"AccessDeniedException", "OptInRequired", "RegionUnsupported"}, codes)
}

// TP4: smithy errors wrapped via fmt.Errorf("...: %w", apiErr) -- the shape SDK
// callers actually produce -- must still be classified as skippable and not
// abort the loop.
func TestContinueOnDenied_WrappedSmithyError_IsClassifiedSkippable(t *testing.T) {
	report := NewSkipReport()
	wrapped := fmt.Errorf("list amplify apps in us-east-1: %w", &fakeAPIError{code: "AccessDeniedException", msg: "denied"})
	plan := regionErrPlan{"us-east-1": wrapped}

	invoked, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)

	require.NoError(t, err, "wrapped skippable errors must not abort the loop")
	assert.Equal(t, 2, invoked, "sibling region must still run")
	require.Equal(t, 1, report.Len())
	assert.Equal(t, "AccessDeniedException", report.Snapshot()[0].ErrorCode,
		"errors.As must unwrap and find the original smithy code")
}

// TP5: SkipReport.Summary() exposes the populated report in the
// operator-facing format. This is the line the recon module prints via the
// deferred summary in list_all_resources.go.
func TestContinueOnDenied_Summary_RendersGroupedReport(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": &fakeAPIError{code: "AccessDeniedException", msg: "denied"},
		"us-west-2": &fakeAPIError{code: "AccessDeniedException", msg: "denied"},
	}
	_, _ = runWithSkipHandling(t, []string{"us-east-1", "us-west-2", "us-east-2"}, plan, report)

	summary := report.Summary()
	assert.Contains(t, summary, "skipped 2 operations across 2 regions",
		"header should reflect total skips and unique regions")
	assert.Contains(t, summary, "amplify ListApps")
	assert.Contains(t, summary, "us-east-1, us-west-2")
	assert.Contains(t, summary, "AccessDeniedException×2")
}

// FP1: a non-AWS, non-skippable error (e.g. a plain network failure that
// doesn't match the region-unsupported substrings) must NOT be swallowed --
// it should propagate up to the recon module so the operator sees a real
// failure rather than a silent loss of coverage.
func TestContinueOnDenied_NonSkippableError_PropagatesFatal(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": errors.New("network connection refused"),
	}

	_, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)

	require.Error(t, err, "non-skippable errors must propagate so operators see them")
	assert.Contains(t, err.Error(), "network connection refused")
	assert.Equal(t, 0, report.Len(),
		"non-skippable errors must NOT be recorded as skips -- that would mask real failures")
}

// FP2: a fatal smithy error (expired credentials) must propagate — it means
// every subsequent call will also fail, so continuing is pointless.
func TestContinueOnDenied_FatalSmithyCode_PropagatesFatal(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": &fakeAPIError{code: "ExpiredToken", msg: "token expired"},
	}

	_, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)

	require.Error(t, err, "ExpiredToken must propagate — credentials are broken")
	assert.Contains(t, err.Error(), "ExpiredToken")
	assert.Equal(t, 0, report.Len())
}

// FP3: an empty smithy error code (no actual ErrorCode set) combined with a
// non-region-unsupported message must propagate. extractAPIErrorCode returns
// ok=false on empty code so this exact shape doesn't leak past IsSkippableAWSError.
func TestContinueOnDenied_EmptySmithyCode_PropagatesFatal(t *testing.T) {
	report := NewSkipReport()
	plan := regionErrPlan{
		"us-east-1": &fakeAPIError{code: "", msg: "weird coreless smithy error"},
	}

	_, err := runWithSkipHandling(t, []string{"us-east-1", "us-east-2"}, plan, report)

	require.Error(t, err, "empty smithy code with non-DNS message must NOT be classified as skippable")
	assert.Equal(t, 0, report.Len())
}

// Concurrency check: drive many regions in parallel, mixing skippable and
// successful outcomes, and assert the SkipReport is correctly aggregated under
// race conditions.
func TestContinueOnDenied_HighConcurrency_AllRecorded(t *testing.T) {
	report := NewSkipReport()

	regions := make([]string, 0, 32)
	plan := regionErrPlan{}
	expectSkips := 0
	for i := 0; i < 32; i++ {
		r := fmt.Sprintf("region-%d", i)
		regions = append(regions, r)
		if i%2 == 0 {
			plan[r] = &fakeAPIError{code: "AccessDeniedException", msg: "denied"}
			expectSkips++
		}
	}

	// Run multiple iterations to flush out races.
	const iterations = 5
	var wg sync.WaitGroup
	errs := make(chan error, iterations)
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := runWithSkipHandling(t, regions, plan, report)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		require.NoError(t, e, "skippable-only runs must not propagate errors")
	}
	assert.Equal(t, expectSkips*iterations, report.Len(),
		"every per-iteration skip should be recorded exactly once")
}
