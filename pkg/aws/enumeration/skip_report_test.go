package enumeration

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkipReport_Empty(t *testing.T) {
	r := NewSkipReport()
	assert.Equal(t, 0, r.Len())
	assert.Empty(t, r.Snapshot())
	assert.Empty(t, r.Summary())
}

func TestSkipReport_RecordTruncatesDetail(t *testing.T) {
	r := NewSkipReport()
	long := strings.Repeat("x", 600)
	r.Record(SkippedOp{Region: "us-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException", Detail: long})

	snap := r.Snapshot()
	require.Len(t, snap, 1)
	assert.Len(t, snap[0].Detail, 500)
}

func TestSkipReport_RecordBatch(t *testing.T) {
	r := NewSkipReport()
	ops := []SkippedOp{
		{Region: "us-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"},
		{Region: "us-west-2", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"},
		{Region: "eu-west-1", Service: "s3", Operation: "ListBuckets", ErrorCode: "AccessDenied", Detail: strings.Repeat("x", 600)},
	}
	r.RecordBatch(ops)

	assert.Equal(t, 3, r.Len())
	snap := r.Snapshot()
	assert.Equal(t, "us-east-1", snap[0].Region)
	assert.Equal(t, "eu-west-1", snap[2].Region)
	assert.Len(t, snap[2].Detail, 500, "RecordBatch should truncate Detail")
}

func TestSkipReport_RecordBatch_Empty(t *testing.T) {
	r := NewSkipReport()
	r.RecordBatch(nil)
	r.RecordBatch([]SkippedOp{})
	assert.Equal(t, 0, r.Len(), "empty batches should not add entries")
}

func TestSkipReport_ConcurrentRecord(t *testing.T) {
	r := NewSkipReport()

	const goroutines = 20
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				r.Record(SkippedOp{
					Region:    "us-east-1",
					Service:   "amplify",
					Operation: "ListApps",
					ErrorCode: "AccessDeniedException",
				})
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines*perGoroutine, r.Len())
}

func TestSkipReport_ConcurrentRecordBatch(t *testing.T) {
	r := NewSkipReport()

	const goroutines = 20
	const opsPerBatch = 10
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch := make([]SkippedOp, opsPerBatch)
			for j := range batch {
				batch[j] = SkippedOp{
					Region: "us-east-1", Service: "amplify",
					Operation: "ListApps", ErrorCode: "AccessDeniedException",
				}
			}
			r.RecordBatch(batch)
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines*opsPerBatch, r.Len())
}

func TestSkipReport_SummaryGroupsAndSorts(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "ap-northeast-3", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "eu-south-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "ap-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "me-south-1", Service: "ec2", Operation: "DescribeImages", ErrorCode: "OptInRequired"})

	got := r.Summary()
	expected := strings.Join([]string{
		"skipped 4 operations across 4 regions:",
		"  amplify ListApps: ap-east-1, ap-northeast-3, eu-south-1 [AccessDeniedException]",
		"  ec2 DescribeImages: me-south-1 [OptInRequired]",
	}, "\n")
	assert.Equal(t, expected, got)
}

func TestSkipReport_SummaryDominantCode(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})
	r.Record(SkippedOp{Region: "us-east-2", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})
	r.Record(SkippedOp{Region: "us-east-3", Service: "iam", Operation: "ListRoles", ErrorCode: "RegionUnsupported"})

	got := r.Summary()
	assert.Contains(t, got, "[AccessDenied]")
}

func TestSkipReport_SummaryDominantCodeTieBreak(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "iam", Operation: "ListRoles", ErrorCode: "OptInRequired"})
	r.Record(SkippedOp{Region: "us-east-2", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})

	got := r.Summary()
	assert.Contains(t, got, "[AccessDenied]")
	assert.NotContains(t, got, "[OptInRequired]")
}

func TestClassifySkippable_Skippable(t *testing.T) {
	err := &fakeAPIError{code: "AccessDeniedException", msg: "denied"}
	op := ClassifySkippable(err, "amplify", "ListApps", "us-east-1")

	require.NotNil(t, op, "skippable error should return a SkippedOp")
	assert.Equal(t, "us-east-1", op.Region)
	assert.Equal(t, "amplify", op.Service)
	assert.Equal(t, "ListApps", op.Operation)
	assert.Equal(t, "AccessDeniedException", op.ErrorCode)
	assert.Contains(t, op.Detail, "denied")
}

func TestClassifySkippable_NonSkippable(t *testing.T) {
	err := errors.New("network connection refused")
	op := ClassifySkippable(err, "amplify", "ListApps", "us-east-1")

	assert.Nil(t, op, "non-skippable error should return nil")
}

func TestClassifySkippable_TruncatesDetail(t *testing.T) {
	longMsg := strings.Repeat("x", 600)
	err := &fakeAPIError{code: "AccessDeniedException", msg: longMsg}
	op := ClassifySkippable(err, "amplify", "ListApps", "us-east-1")

	require.NotNil(t, op)
	assert.Len(t, op.Detail, 500)
}
