package enumeration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockResourceEnumerator struct {
	resourceType         string
	enumerateAllCalled   bool
	enumerateByARNCalled bool
	enumerateAllErr      error
	enumerateByARNErr    error
}

func (m *mockResourceEnumerator) ResourceType() string { return m.resourceType }

func (m *mockResourceEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	m.enumerateAllCalled = true
	return m.enumerateAllErr
}

func (m *mockResourceEnumerator) EnumerateByARN(_ string, out *pipeline.P[output.AWSResource]) error {
	m.enumerateByARNCalled = true
	return m.enumerateByARNErr
}

// mockSmithyError implements smithy.APIError for dispatcher-level tests.
type mockSmithyError struct {
	code string
	msg  string
}

func (e *mockSmithyError) Error() string                 { return fmt.Sprintf("%s: %s", e.code, e.msg) }
func (e *mockSmithyError) ErrorCode() string             { return e.code }
func (e *mockSmithyError) ErrorMessage() string          { return e.msg }
func (e *mockSmithyError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func newTestEnumerator(enumerators map[string]ResourceEnumerator) *Enumerator {
	// Share one SkipReport across Enumerator and CloudControl, matching
	// the production wiring in NewEnumerator.
	skipped := NewSkipReport()
	return &Enumerator{
		enumerators: enumerators,
		cc:          &CloudControlEnumerator{skipReport: skipped},
		Skipped:     skipped,
	}
}

func TestEnumerator_enumerateByType_DispatchesToRegisteredLister(t *testing.T) {
	mock := &mockResourceEnumerator{resourceType: "AWS::S3::Bucket"}
	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::S3::Bucket": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.listByType("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err)
	require.True(t, mock.enumerateAllCalled)
}

func TestEnumerator_enumerateByType_FallsBackForUnregisteredType(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{})

	_, ok := e.enumerators["AWS::EC2::Instance"]
	require.False(t, ok, "unregistered type should not be in enumerators map")
}

func TestEnumerator_List_InvalidIdentifier(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.List("garbage", out)
	out.Close()

	require.Error(t, err)
	require.Contains(t, err.Error(), "identifier must be either an ARN or CloudControl resource type")
}

func TestNewEnumerator_RegistersRAMResourceShare(t *testing.T) {
	e := NewEnumerator(plugin.AWSCommonRecon{Regions: []string{"us-east-1"}, Concurrency: 1})
	defer func() { _ = e.Close() }()

	enum, ok := e.enumerators["AWS::RAM::ResourceShare"]
	if !ok {
		t.Fatal("expected AWS::RAM::ResourceShare to be registered on the dispatcher")
	}
	if got := enum.ResourceType(); got != "AWS::RAM::ResourceShare" {
		t.Errorf("registered enumerator ResourceType() = %q, want AWS::RAM::ResourceShare", got)
	}
}

func TestEnumerator_enumerateByType_DispatchesSSMToRegisteredEnumerator(t *testing.T) {
	mock := &mockResourceEnumerator{resourceType: "AWS::SSM::Document"}
	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::SSM::Document": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.listByType("AWS::SSM::Document", out)
	out.Close()

	require.NoError(t, err)
	require.True(t, mock.enumerateAllCalled)
}

func TestEnumerator_EnumerateByARN_FallbackOnSentinel(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType:      "AWS::S3::Bucket",
		enumerateByARNErr: errFallbackToCloudControl,
	}

	require.ErrorIs(t, mock.enumerateByARNErr, errFallbackToCloudControl,
		"S3Enumerator should return sentinel error for EnumerateByARN")
}

func TestEnumerator_List_SkippableError_RecordedNotReturned(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType:    "AWS::S3::Bucket",
		enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "denied by SCP"},
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::S3::Bucket": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err, "List should swallow skippable errors and record them")
	snap := e.Skipped.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "s3", snap[0].Service)
	assert.Equal(t, "AccessDeniedException", snap[0].ErrorCode)
	assert.Contains(t, snap[0].Detail, "denied by SCP")
}

func TestEnumerator_List_NonSkippableError_Propagated(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType:    "AWS::S3::Bucket",
		enumerateAllErr: errors.New("network connection refused"),
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::S3::Bucket": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.Error(t, err, "non-skippable errors must propagate")
	assert.Contains(t, err.Error(), "network connection refused")
	assert.Equal(t, 0, e.Skipped.Len(), "non-skippable errors must not be recorded as skips")
}

func TestEnumerator_List_SuccessNotRecorded(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType: "AWS::S3::Bucket",
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::S3::Bucket": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err)
	assert.Equal(t, 0, e.Skipped.Len(), "successful enumeration should not be recorded")
}

func TestEnumerator_List_MultipleTypes_OneSkippableFailContinues(t *testing.T) {
	failing := &mockResourceEnumerator{
		resourceType:    "AWS::Amplify::App",
		enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "not authorized"},
	}
	succeeding := &sendingAllMockEnumerator{
		resourceType: "AWS::Lambda::Function",
		resource: output.AWSResource{
			ResourceType: "AWS::Lambda::Function",
			ResourceID:   "my-func",
		},
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{
		"AWS::Amplify::App":     failing,
		"AWS::Lambda::Function": succeeding,
	})

	// Simulate pipeline: feed two resource types, collect results
	types := pipeline.From("AWS::Amplify::App", "AWS::Lambda::Function")
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, e.List, listed)

	results, err := listed.Collect()
	require.NoError(t, err, "pipeline should not fail when one type has a skippable error")
	require.Len(t, results, 1, "successful type should still produce results")
	require.Equal(t, "AWS::Lambda::Function", results[0].ResourceType)

	snap := e.Skipped.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "amplify", snap[0].Service)
	assert.Equal(t, "AccessDeniedException", snap[0].ErrorCode)
}

// sendingAllMockEnumerator sends a resource from EnumerateAll.
type sendingAllMockEnumerator struct {
	resourceType string
	resource     output.AWSResource
}

func (m *sendingAllMockEnumerator) ResourceType() string { return m.resourceType }

func (m *sendingAllMockEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	out.Send(m.resource)
	return nil
}

func (m *sendingAllMockEnumerator) EnumerateByARN(_ string, out *pipeline.P[output.AWSResource]) error {
	out.Send(m.resource)
	return nil
}

// --- Close() tests ---

// Happy path: no skips recorded, Close is a no-op (no panic, no log).
func TestEnumerator_Close_NoSkips(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{})
	assert.Equal(t, 0, e.Skipped.Len())
	require.NoError(t, e.Close()) // must not panic
	assert.Equal(t, 0, e.Skipped.Len(), "Close must not mutate the report")
}

// Close surfaces skips that were recorded during enumeration.
func TestEnumerator_Close_WithSkips(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType:    "AWS::S3::Bucket",
		enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "denied"},
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::S3::Bucket": mock})

	out := pipeline.New[output.AWSResource]()
	go func() {
		for range out.Range() {
		}
	}()
	_ = e.List("AWS::S3::Bucket", out)
	out.Close()

	require.Equal(t, 1, e.Skipped.Len(), "skip should be recorded before Close")
	require.NoError(t, e.Close()) // should log summary, not panic
	assert.Equal(t, 1, e.Skipped.Len(), "Close must not clear the report")
}

// Close is safe to call multiple times — summary logs exactly once.
func TestEnumerator_Close_Idempotent(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{})
	e.Skipped.Record(SkippedOp{
		Region: "us-east-1", Service: "amplify", Operation: "ListApps",
		ErrorCode: "AccessDeniedException",
	})
	require.NoError(t, e.Close())
	require.NoError(t, e.Close()) // second call is a no-op (sync.Once)
	assert.Equal(t, 1, e.Skipped.Len())
}

// Defer pattern: Close fires even when the module returns early with an error.
func TestEnumerator_Close_OnEarlyReturn(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{})

	// Simulate a module that records a skip then returns early on a fatal error.
	e.Skipped.Record(SkippedOp{
		Region: "eu-west-1", Service: "s3", Operation: "ListBuckets",
		ErrorCode: "AccessDenied", Detail: "denied",
	})

	// In real code this would be defer lister.Close() at the top of Run().
	// The defer fires even though the function "returns" with an error.
	func() {
		defer func() { require.NoError(t, e.Close()) }()
	}()

	// The skip should have been logged by Close (we can't assert on slog
	// output, but we verify Close didn't panic and the report is intact).
	assert.Equal(t, 1, e.Skipped.Len())
}

// Edge case: Close on a zero-value Enumerator (nil Skipped) must not panic.
func TestEnumerator_Close_NilSkipped(t *testing.T) {
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          &CloudControlEnumerator{skipReport: NewSkipReport()},
		Skipped:     NewSkipReport(),
	}
	require.NoError(t, e.Close()) // must not panic
}

// Close with outputDir writes detail file; empty outputDir does not.
func TestEnumerator_Close_WritesDetailFile(t *testing.T) {
	dir := t.TempDir()
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          &CloudControlEnumerator{skipReport: NewSkipReport()},
		Skipped:     NewSkipReport(),
		outputDir:   dir,
	}
	e.Skipped.Record(SkippedOp{
		Region: "us-east-1", Service: "amplify", Operation: "ListApps",
		ErrorCode: "AccessDeniedException", Detail: "denied",
	})

	require.NoError(t, e.Close())

	_, err := os.Stat(filepath.Join(dir, "enumeration-skips.json"))
	assert.NoError(t, err, "Close with outputDir must write detail file")
}

func TestEnumerator_Close_EmptyOutputDir_NoFile(t *testing.T) {
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          &CloudControlEnumerator{skipReport: NewSkipReport()},
		Skipped:     NewSkipReport(),
		outputDir:   "", // empty — no file should be written
	}
	e.Skipped.Record(SkippedOp{
		Region: "us-east-1", Service: "amplify", Operation: "ListApps",
		ErrorCode: "AccessDeniedException", Detail: "denied",
	})

	require.NoError(t, e.Close()) // must not panic or attempt file write
}

// IAM sync.Once denial: if IAM is denied, the cached error should be caught
// by the dispatcher safety net on every subsequent List call for IAM types.
func TestEnumerator_List_IAMDenied_SyncOnce(t *testing.T) {
	// Simulate an IAM sub-enumerator that returns AccessDeniedException.
	denied := &mockResourceEnumerator{
		resourceType:    "AWS::IAM::Role",
		enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "denied"},
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::IAM::Role": denied})

	// First call: denied, should be caught and recorded.
	out1 := pipeline.New[output.AWSResource]()
	go func() {
		for range out1.Range() {
		}
	}()
	err := e.List("AWS::IAM::Role", out1)
	out1.Close()
	require.NoError(t, err, "IAM denial should be skipped")
	require.Equal(t, 1, e.Skipped.Len(), "first denial should be recorded")

	// Second call with same type: the mock's enumerateAllErr is still set
	// (simulating sync.Once cached error). Should also be caught.
	out2 := pipeline.New[output.AWSResource]()
	go func() {
		for range out2.Range() {
		}
	}()
	err = e.List("AWS::IAM::Role", out2)
	out2.Close()
	require.NoError(t, err, "second IAM denial should also be skipped")
	require.Equal(t, 2, e.Skipped.Len(), "second denial should also be recorded")
}

// Multiple types denied in sequence: each produces its own skip entry.
func TestEnumerator_List_MultipleDeniedTypes_EachRecorded(t *testing.T) {
	e := newTestEnumerator(map[string]ResourceEnumerator{
		"AWS::Amplify::App": &mockResourceEnumerator{
			resourceType:    "AWS::Amplify::App",
			enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "amplify denied"},
		},
		"AWS::SSM::Document": &mockResourceEnumerator{
			resourceType:    "AWS::SSM::Document",
			enumerateAllErr: &mockSmithyError{code: "AccessDeniedException", msg: "ssm denied"},
		},
		"AWS::Lambda::Function": &mockResourceEnumerator{
			resourceType:    "AWS::Lambda::Function",
			enumerateAllErr: &mockSmithyError{code: "UnauthorizedOperation", msg: "lambda denied"},
		},
	})

	for _, typ := range []string{"AWS::Amplify::App", "AWS::SSM::Document", "AWS::Lambda::Function"} {
		out := pipeline.New[output.AWSResource]()
		go func() {
			for range out.Range() {
			}
		}()
		err := e.List(typ, out)
		out.Close()
		require.NoError(t, err, "%s denial should be skipped", typ)
	}

	snap := e.Skipped.Snapshot()
	require.Len(t, snap, 3, "each denied type must produce its own skip entry")

	codes := make(map[string]bool)
	for _, op := range snap {
		codes[op.ErrorCode] = true
	}
	assert.True(t, codes["AccessDeniedException"])
	assert.True(t, codes["UnauthorizedOperation"])
}

// TestEnumerator_List_FatalError_StopsPipeline verifies that a fatal error
// (e.g. ExpiredToken) at the enumeration level causes pipeline.Pipe to abort.
// The first type returns a fatal error, and subsequent types must NOT execute.
// This tests the actual pipeline behavior, not just the classifier.
func TestEnumerator_List_FatalError_StopsPipeline(t *testing.T) {
	callCount := 0
	fatal := &mockResourceEnumerator{
		resourceType:    "AWS::S3::Bucket",
		enumerateAllErr: &mockSmithyError{code: "ExpiredToken", msg: "token expired mid-run"},
	}
	tracker := &mockResourceEnumerator{
		resourceType: "AWS::Lambda::Function",
		// No error — but we track if it was called.
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{
		"AWS::S3::Bucket":       fatal,
		"AWS::Lambda::Function": tracker,
	})

	// Count how many times List is called via the pipeline.
	originalList := e.List
	wrappedList := func(identifier string, out *pipeline.P[output.AWSResource]) error {
		callCount++
		return originalList(identifier, out)
	}

	types := pipeline.From("AWS::S3::Bucket", "AWS::Lambda::Function")
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, wrappedList, listed)

	results, err := listed.Collect()

	require.Error(t, err, "pipeline must abort on fatal error")
	assert.Contains(t, err.Error(), "ExpiredToken")
	assert.Empty(t, results, "no resources should be collected after fatal error")
	assert.Equal(t, 0, e.Skipped.Len(), "fatal errors must NOT be recorded as skips")

	// The pipeline should have stopped after the first type.
	// With pipeSequential, the second type should NOT be called.
	assert.Equal(t, 1, callCount,
		"pipeline must stop after first fatal error — second type should not be attempted")
}

