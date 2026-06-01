package enumeration

import (
	"fmt"
	"strings"
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

// TestEnumerateByARN_DispatcherExtractsServiceAndRegion verifies that the
// dispatcher safety net extracts the short service name and region from every
// ARN format, not passing the full ARN as the service. This prevents
// high-cardinality SkipReport entries like Service="arn:aws:amplify:...".
//
// Each ARN is routed to a mock enumerator that returns AccessDeniedException.
// The error flows to handleListError which must record service/region from the
// parsed ARN. If someone regresses handleListError to pass the raw identifier,
// these assertions catch it.
func TestEnumerateByARN_DispatcherExtractsServiceAndRegion(t *testing.T) {
	tests := []struct {
		arn             string
		resourceType    string // what types.ResolveResourceType maps to
		expectedService string
		expectedRegion  string
	}{
		{"arn:aws:lambda:us-east-1:123456789012:function:my-func", "AWS::Lambda::Function", "lambda", "us-east-1"},
		{"arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890", "AWS::EC2::Instance", "ec2", "us-west-2"},
		{"arn:aws:iam::123456789012:role/my-role", "AWS::IAM::Role", "iam", ""},
		{"arn:aws:amplify:eu-west-1:123456789012:apps/abc123", "AWS::Amplify::App", "amplify", "eu-west-1"},
		{"arn:aws:dynamodb:ap-southeast-1:123456789012:table/my-table", "AWS::DynamoDB::Table", "dynamodb", "ap-southeast-1"},
		{"arn:aws:ssm:us-east-2:123456789012:document/my-doc", "AWS::SSM::Document", "ssm", "us-east-2"},
	}

	for _, tc := range tests {
		t.Run(tc.expectedService, func(t *testing.T) {
			mock := &mockResourceEnumerator{
				resourceType:      tc.resourceType,
				enumerateByARNErr: &ccTestSmithyError{code: "AccessDeniedException", msg: "denied"},
			}

			e := newTestEnumerator(map[string]ResourceEnumerator{
				tc.resourceType: mock,
			})

			out := pipeline.New[output.AWSResource]()
			go func() { for range out.Range() {} }()
			err := e.List(tc.arn, out)
			out.Close()

			require.NoError(t, err, "ARN %s should be skipped", tc.arn)
			snap := e.Skipped.Snapshot()
			require.NotEmpty(t, snap, "ARN %s should produce a skip entry", tc.arn)

			last := snap[len(snap)-1]
			assert.Equal(t, tc.expectedService, last.Service,
				"ARN %s: service should be %q, not the full ARN", tc.arn, tc.expectedService)
			assert.Equal(t, tc.expectedRegion, last.Region,
				"ARN %s: region should be %q", tc.arn, tc.expectedRegion)
			assert.False(t, strings.Contains(last.Service, "arn:"),
				"service must never contain 'arn:' — that indicates the full ARN was passed")
		})
	}
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
