package enumeration

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Summary: few regions — listed inline.
func TestSkipReport_Summary_FewRegions(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "ap-northeast-3", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "eu-south-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "ap-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	r.Record(SkippedOp{Region: "me-south-1", Service: "ec2", Operation: "DescribeImages", ErrorCode: "OptInRequired"})

	got := r.Summary()
	expected := strings.Join([]string{
		"skipped 4 operations across 4 regions:",
		"  amplify ListApps: ap-east-1, ap-northeast-3, eu-south-1 [AccessDeniedException×3]",
		"  ec2 DescribeImages: me-south-1 [OptInRequired]",
	}, "\n")
	assert.Equal(t, expected, got)
}

// Summary: many regions — collapsed to count.
func TestSkipReport_Summary_ManyRegions(t *testing.T) {
	r := NewSkipReport()
	for _, region := range []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"} {
		r.Record(SkippedOp{Region: region, Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException"})
	}

	got := r.Summary()
	assert.Contains(t, got, "6 regions")
	assert.NotContains(t, got, "us-east-1,", "regions should be collapsed, not listed")
}

// Summary: exactly at threshold — still listed inline.
func TestSkipReport_Summary_ExactThreshold(t *testing.T) {
	r := NewSkipReport()
	for _, region := range []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1"} {
		r.Record(SkippedOp{Region: region, Service: "s3", Operation: "ListBuckets", ErrorCode: "AccessDenied"})
	}

	got := r.Summary()
	assert.Contains(t, got, "eu-west-1, us-east-1, us-east-2, us-west-1, us-west-2")
}

// Summary: multiple error codes shown with counts.
func TestSkipReport_Summary_MultipleCodes(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})
	r.Record(SkippedOp{Region: "us-east-2", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})
	r.Record(SkippedOp{Region: "us-east-3", Service: "iam", Operation: "ListRoles", ErrorCode: "RegionUnsupported"})

	got := r.Summary()
	assert.Contains(t, got, "AccessDenied×2")
	assert.Contains(t, got, "RegionUnsupported")
}

// Summary: single occurrence of a code omits the ×N suffix.
func TestSkipReport_Summary_SingleCodeNoCount(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "ec2", Operation: "DescribeImages", ErrorCode: "OptInRequired"})

	got := r.Summary()
	assert.Contains(t, got, "[OptInRequired]")
	assert.NotContains(t, got, "×")
}

// Summary: tie between codes — both shown alphabetically.
func TestSkipReport_Summary_CodeTieBothShown(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "iam", Operation: "ListRoles", ErrorCode: "OptInRequired"})
	r.Record(SkippedOp{Region: "us-east-2", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied"})

	got := r.Summary()
	assert.Contains(t, got, "AccessDenied")
	assert.Contains(t, got, "OptInRequired")
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

// WriteDetailFile: creates JSON with all fields.
func TestSkipReport_WriteDetailFile(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{
		Region: "us-east-1", Service: "amplify", Operation: "ListApps",
		ErrorCode: "AccessDeniedException", Detail: "denied by SCP",
	})
	r.Record(SkippedOp{
		Region: "eu-west-1", Service: "s3", Operation: "ListBuckets",
		ErrorCode: "AccessDenied", Detail: "no access",
	})

	dir := t.TempDir()
	require.NoError(t, r.WriteDetailFile(dir))

	path := filepath.Join(dir, "enumeration-skips.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var ops []SkippedOp
	require.NoError(t, json.Unmarshal(data, &ops))
	require.Len(t, ops, 2)
	assert.Equal(t, "us-east-1", ops[0].Region)
	assert.Equal(t, "amplify", ops[0].Service)
	assert.Equal(t, "AccessDeniedException", ops[0].ErrorCode)
	assert.Equal(t, "denied by SCP", ops[0].Detail)
	assert.Equal(t, "eu-west-1", ops[1].Region)
}

// WriteDetailFile: all recorded ops appear in the file — no loss.
func TestSkipReport_WriteDetailFile_Completeness(t *testing.T) {
	r := NewSkipReport()

	// Record a mix of services, regions, codes to verify nothing is lost.
	expected := []SkippedOp{
		{Region: "us-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException", Detail: "denied"},
		{Region: "us-west-2", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException", Detail: "denied"},
		{Region: "eu-west-1", Service: "s3", Operation: "ListBuckets", ErrorCode: "AccessDenied", Detail: "no access"},
		{Region: "ap-northeast-1", Service: "ec2", Operation: "DescribeImages", ErrorCode: "OptInRequired", Detail: "region not opted in"},
		{Region: "global", Service: "iam", Operation: "ListRoles", ErrorCode: "AccessDenied", Detail: "iam denied"},
		{Region: "us-east-1", Service: "cloudcontrol", Operation: "ListResources", ErrorCode: "TypeNotFoundException", Detail: "type not found"},
		{Region: "us-east-1", Service: "ssm", Operation: "ListDocuments", ErrorCode: "RegionUnsupported", Detail: "no such host"},
	}
	for _, op := range expected {
		r.Record(op)
	}

	dir := t.TempDir()
	require.NoError(t, r.WriteDetailFile(dir))

	data, err := os.ReadFile(filepath.Join(dir, "enumeration-skips.json"))
	require.NoError(t, err)

	var got []SkippedOp
	require.NoError(t, json.Unmarshal(data, &got))
	require.Len(t, got, len(expected), "file must contain exactly as many ops as recorded")

	for i, want := range expected {
		assert.Equal(t, want.Region, got[i].Region, "op[%d] Region", i)
		assert.Equal(t, want.Service, got[i].Service, "op[%d] Service", i)
		assert.Equal(t, want.Operation, got[i].Operation, "op[%d] Operation", i)
		assert.Equal(t, want.ErrorCode, got[i].ErrorCode, "op[%d] ErrorCode", i)
		assert.Equal(t, want.Detail, got[i].Detail, "op[%d] Detail", i)
	}
}

// WriteDetailFile: concurrent writes then file — nothing lost.
func TestSkipReport_WriteDetailFile_AfterConcurrentWrites(t *testing.T) {
	r := NewSkipReport()

	const goroutines = 10
	const perGoroutine = 20
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			batch := make([]SkippedOp, perGoroutine)
			for j := range batch {
				batch[j] = SkippedOp{
					Region:    "us-east-1",
					Service:   "amplify",
					Operation: "ListApps",
					ErrorCode: "AccessDeniedException",
					Detail:    "denied",
				}
			}
			r.RecordBatch(batch)
		}(i)
	}
	wg.Wait()

	dir := t.TempDir()
	require.NoError(t, r.WriteDetailFile(dir))

	data, err := os.ReadFile(filepath.Join(dir, "enumeration-skips.json"))
	require.NoError(t, err)

	var got []SkippedOp
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, goroutines*perGoroutine, len(got),
		"file must contain every op from all goroutines, no loss")
}

// WriteDetailFile and Summary must agree: the total count in the summary
// header must equal the number of entries in the detail file.
func TestSkipReport_DetailAndSummaryInSync(t *testing.T) {
	r := NewSkipReport()
	r.Record(SkippedOp{Region: "us-east-1", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException", Detail: "d1"})
	r.Record(SkippedOp{Region: "us-west-2", Service: "amplify", Operation: "ListApps", ErrorCode: "AccessDeniedException", Detail: "d2"})
	r.Record(SkippedOp{Region: "eu-west-1", Service: "s3", Operation: "ListBuckets", ErrorCode: "AccessDenied", Detail: "d3"})
	r.Record(SkippedOp{Region: "ap-northeast-1", Service: "ec2", Operation: "DescribeImages", ErrorCode: "OptInRequired", Detail: "d4"})
	r.Record(SkippedOp{Region: "us-east-1", Service: "ssm", Operation: "ListDocuments", ErrorCode: "AccessDeniedException", Detail: "d5"})

	// Write detail file.
	dir := t.TempDir()
	require.NoError(t, r.WriteDetailFile(dir))

	data, err := os.ReadFile(filepath.Join(dir, "enumeration-skips.json"))
	require.NoError(t, err)
	var detail []SkippedOp
	require.NoError(t, json.Unmarshal(data, &detail))

	// Summary and detail must agree on total count.
	summary := r.Summary()
	assert.Contains(t, summary, fmt.Sprintf("skipped %d operations", len(detail)),
		"summary header count must match detail file entry count")

	// Every service+operation group in the summary must have entries in the detail file.
	detailServices := make(map[string]int)
	for _, op := range detail {
		key := op.Service + " " + op.Operation
		detailServices[key]++
	}
	for key, count := range detailServices {
		assert.Contains(t, summary, key,
			"detail file has %d entries for %q but it's missing from summary", count, key)
	}

	// Every region in the detail file must be accounted for in the summary
	// (either listed inline or collapsed into a count).
	detailRegions := make(map[string]struct{})
	for _, op := range detail {
		detailRegions[op.Region] = struct{}{}
	}
	assert.Contains(t, summary, fmt.Sprintf("%d regions", len(detailRegions)),
		"summary header region count must match unique regions in detail file")
}

// WriteDetailFile: no ops — no file created.
func TestSkipReport_WriteDetailFile_Empty(t *testing.T) {
	r := NewSkipReport()
	dir := t.TempDir()
	require.NoError(t, r.WriteDetailFile(dir))

	path := filepath.Join(dir, "enumeration-skips.json")
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "empty report should not create a file")
}
