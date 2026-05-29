package enumeration

import (
	"errors"
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
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
	go func() { for range out.Range() {} }()

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
	go func() { for range out.Range() {} }()

	err := e.List("garbage", out)
	out.Close()

	require.Error(t, err)
	require.Contains(t, err.Error(), "identifier must be either an ARN or CloudControl resource type")
}

func TestEnumerator_enumerateByType_DispatchesSSMToRegisteredEnumerator(t *testing.T) {
	mock := &mockResourceEnumerator{resourceType: "AWS::SSM::Document"}
	e := newTestEnumerator(map[string]ResourceEnumerator{"AWS::SSM::Document": mock})

	out := pipeline.New[output.AWSResource]()
	go func() { for range out.Range() {} }()

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
	go func() { for range out.Range() {} }()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err, "List should swallow skippable errors and record them")
	snap := e.Skipped.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "AWS::S3::Bucket", snap[0].Service)
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
	go func() { for range out.Range() {} }()

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
	go func() { for range out.Range() {} }()

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
	assert.Equal(t, "AWS::Amplify::App", snap[0].Service)
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
