package enumeration

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerateByARN_ErrorDoesNotSendZeroResource(t *testing.T) {
	// A mock enumerator that always returns an error from EnumerateByARN.
	mock := &mockResourceEnumerator{
		resourceType:      "AWS::Lambda::Function",
		enumerateByARNErr: errors.New("GetResource failed"),
	}

	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{
			"AWS::Lambda::Function": mock,
		},
		cc: &CloudControlEnumerator{},
	}

	out := pipeline.New[output.AWSResource]()
	var collected []output.AWSResource

	done := make(chan struct{})
	go func() {
		defer close(done)
		for item := range out.Range() {
			collected = append(collected, item)
		}
	}()

	err := e.List(
		"arn:aws:lambda:us-east-1:123456789012:function:my-func",
		out,
	)
	out.Close()
	<-done

	require.Error(t, err)
	assert.Empty(t, collected, "no resources should be sent when EnumerateByARN returns an error")
}

func TestEnumerateByARN_SuccessSendsResource(t *testing.T) {
	expected := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-func",
		Region:       "us-east-1",
	}

	mock := &sendingMockEnumerator{
		resourceType: "AWS::Lambda::Function",
		resource:     expected,
	}

	e := &Enumerator{
		enumerators: map[string]ResourceEnumerator{
			"AWS::Lambda::Function": mock,
		},
		cc: &CloudControlEnumerator{},
	}

	out := pipeline.New[output.AWSResource]()
	var collected []output.AWSResource

	done := make(chan struct{})
	go func() {
		defer close(done)
		for item := range out.Range() {
			collected = append(collected, item)
		}
	}()

	err := e.List(
		"arn:aws:lambda:us-east-1:123456789012:function:my-func",
		out,
	)
	out.Close()
	<-done

	require.NoError(t, err)
	require.Len(t, collected, 1)
	assert.Equal(t, "AWS::Lambda::Function", collected[0].ResourceType)
	assert.Equal(t, "my-func", collected[0].ResourceID)
}

// sendingMockEnumerator sends a resource on success.
type sendingMockEnumerator struct {
	resourceType string
	resource     output.AWSResource
}

func (m *sendingMockEnumerator) ResourceType() string { return m.resourceType }

func (m *sendingMockEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	return nil
}

func (m *sendingMockEnumerator) EnumerateByARN(_ string, out *pipeline.P[output.AWSResource]) error {
	out.Send(m.resource)
	return nil
}
