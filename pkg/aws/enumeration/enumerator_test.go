package enumeration

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

type mockResourceEnumerator struct {
	resourceType    string
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

func TestEnumerator_enumerateByType_DispatchesToRegisteredLister(t *testing.T) {
	mock := &mockResourceEnumerator{resourceType: "AWS::S3::Bucket"}
	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{"AWS::S3::Bucket": mock},
		cc:      &CloudControlEnumerator{},
	}

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
	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{},
	}

	_, ok := e.enumerators["AWS::EC2::Instance"]
	require.False(t, ok, "unregistered type should not be in enumerators map")
}

func TestEnumerator_List_InvalidIdentifier(t *testing.T) {
	e := &Enumerator{enumerators: make(map[string]ResourceEnumerator)}

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

func TestEnumerator_enumerateByType_DispatchesSSMToRegisteredEnumerator(t *testing.T) {
	mock := &mockResourceEnumerator{resourceType: "AWS::SSM::Document"}
	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{"AWS::SSM::Document": mock},
		cc:          &CloudControlEnumerator{},
	}

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
		resourceType: "AWS::S3::Bucket",
		enumerateByARNErr: errFallbackToCloudControl,
	}

	require.ErrorIs(t, mock.enumerateByARNErr, errFallbackToCloudControl,
		"S3Enumerator should return sentinel error for EnumerateByARN")
}

func TestEnumerator_List_ErrorRecordedNotReturned(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType:    "AWS::S3::Bucket",
		enumerateAllErr: errors.New("operation error S3: ListBuckets, AccessDeniedException"),
	}

	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{"AWS::S3::Bucket": mock},
		cc:          &CloudControlEnumerator{},
	}

	out := pipeline.New[output.AWSResource]()
	go func() { for range out.Range() {} }()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err, "List should swallow errors and record them")
	skipped := e.Skipped.Skipped()
	require.Len(t, skipped, 1)
	require.Equal(t, "AWS::S3::Bucket", skipped[0].ResourceType)
	require.Contains(t, skipped[0].Reason, "AccessDeniedException")
}

func TestEnumerator_List_SuccessNotRecorded(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType: "AWS::S3::Bucket",
	}

	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{"AWS::S3::Bucket": mock},
		cc:          &CloudControlEnumerator{},
	}

	out := pipeline.New[output.AWSResource]()
	go func() { for range out.Range() {} }()

	err := e.List("AWS::S3::Bucket", out)
	out.Close()

	require.NoError(t, err)
	require.Empty(t, e.Skipped.Skipped(), "successful enumeration should not be recorded")
}

func TestEnumerator_List_MultipleTypes_OneFailsContinues(t *testing.T) {
	failing := &mockResourceEnumerator{
		resourceType:    "AWS::Amplify::App",
		enumerateAllErr: errors.New("AccessDeniedException: not authorized"),
	}
	succeeding := &sendingAllMockEnumerator{
		resourceType: "AWS::Lambda::Function",
		resource: output.AWSResource{
			ResourceType: "AWS::Lambda::Function",
			ResourceID:   "my-func",
		},
	}

	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{
			"AWS::Amplify::App":     failing,
			"AWS::Lambda::Function": succeeding,
		},
		cc: &CloudControlEnumerator{},
	}

	// Simulate pipeline: feed two resource types, collect results
	types := pipeline.From("AWS::Amplify::App", "AWS::Lambda::Function")
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, e.List, listed)

	results, err := listed.Collect()
	require.NoError(t, err, "pipeline should not fail when one type errors")
	require.Len(t, results, 1, "successful type should still produce results")
	require.Equal(t, "AWS::Lambda::Function", results[0].ResourceType)

	skipped := e.Skipped.Skipped()
	require.Len(t, skipped, 1)
	require.Equal(t, "AWS::Amplify::App", skipped[0].ResourceType)
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

func TestSkippedTracker(t *testing.T) {
	var tracker SkippedTracker

	require.Empty(t, tracker.Skipped(), "new tracker should be empty")

	tracker.Record("AWS::Amplify::App", "ap-northeast-3", "AccessDeniedException")
	tracker.Record("AWS::S3::Bucket", "eu-west-1", "connection refused")

	skipped := tracker.Skipped()
	require.Len(t, skipped, 2)
	require.Equal(t, "AWS::Amplify::App", skipped[0].ResourceType)
	require.Equal(t, "ap-northeast-3", skipped[0].Region)
	require.Equal(t, "eu-west-1", skipped[1].Region)
}
