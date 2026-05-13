package enumeration

import (
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
	// Equal counts: one AccessDenied, one OptInRequired in the same group.
	// Alphabetically AccessDenied < OptInRequired, so AccessDenied wins.
	r.Record(SkippedOp{Region: "us-east-1", Service: "iam", Operation: "ListRoles", ErrorCode: "OptInRequired"})
	r.Record(SkippedOp{Region: "us-east-2", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})

	got := r.Summary()
	assert.Contains(t, got, "[AccessDenied]")
	assert.NotContains(t, got, "[OptInRequired]")
}
