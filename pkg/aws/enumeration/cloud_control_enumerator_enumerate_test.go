package enumeration

import (
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ccTestSmithyError implements smithy.APIError for cloud control tests.
type ccTestSmithyError struct {
	code string
	msg  string
}

func (e *ccTestSmithyError) Error() string                 { return fmt.Sprintf("%s: %s", e.code, e.msg) }
func (e *ccTestSmithyError) ErrorCode() string             { return e.code }
func (e *ccTestSmithyError) ErrorMessage() string          { return e.msg }
func (e *ccTestSmithyError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestEnumerateByARN_ErrorDoesNotSendZeroResource(t *testing.T) {
	// A mock enumerator that returns a skippable error from EnumerateByARN.
	mock := &mockResourceEnumerator{
		resourceType:      "AWS::Lambda::Function",
		enumerateByARNErr: &ccTestSmithyError{code: "AccessDeniedException", msg: "denied by SCP"},
	}

	e := newTestEnumerator(map[string]ResourceEnumerator{
		"AWS::Lambda::Function": mock,
	})

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

	require.NoError(t, err, "List should not return error — skippable errors are recorded in SkipReport")
	assert.Empty(t, collected, "no resources should be sent when EnumerateByARN returns an error")
	require.True(t, e.Skipped.Len() > 0, "error should be recorded in SkipReport")

	// Dispatcher safety net should extract service/region from the ARN.
	snap := e.Skipped.Snapshot()
	assert.Equal(t, "lambda", snap[0].Service, "service should be extracted from ARN, not the full ARN")
	assert.Equal(t, "us-east-1", snap[0].Region, "region should be extracted from ARN")
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

	e := newTestEnumerator(map[string]ResourceEnumerator{
		"AWS::Lambda::Function": mock,
	})

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
