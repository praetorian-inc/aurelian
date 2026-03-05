package enumeration

import (
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

func TestEnumerator_EnumerateByARN_FallbackOnSentinel(t *testing.T) {
	mock := &mockResourceEnumerator{
		resourceType: "AWS::S3::Bucket",
		enumerateByARNErr: errFallbackToCloudControl,
	}

	require.ErrorIs(t, mock.enumerateByARNErr, errFallbackToCloudControl,
		"S3Enumerator should return sentinel error for EnumerateByARN")
}
