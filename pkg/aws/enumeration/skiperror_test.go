package enumeration

import (
	"errors"
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
)

// fakeAPIError implements smithy.APIError for tests.
type fakeAPIError struct {
	code string
	msg  string
}

func (e *fakeAPIError) Error() string                 { return fmt.Sprintf("%s: %s", e.code, e.msg) }
func (e *fakeAPIError) ErrorCode() string             { return e.code }
func (e *fakeAPIError) ErrorMessage() string          { return e.msg }
func (e *fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestIsSkippableAWSError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"AccessDenied", &fakeAPIError{code: "AccessDenied"}, true},
		{"AccessDeniedException", &fakeAPIError{code: "AccessDeniedException"}, true},
		{"UnauthorizedOperation", &fakeAPIError{code: "UnauthorizedOperation"}, true},
		{"AuthFailure", &fakeAPIError{code: "AuthFailure"}, true},
		{"OptInRequired", &fakeAPIError{code: "OptInRequired"}, true},
		{"InvalidClientTokenId", &fakeAPIError{code: "InvalidClientTokenId"}, true},
		{"UnrecognizedClientException", &fakeAPIError{code: "UnrecognizedClientException"}, true},
		{"TypeNotFoundException", &fakeAPIError{code: "TypeNotFoundException"}, true},
		{"UnsupportedActionException", &fakeAPIError{code: "UnsupportedActionException"}, true},
		{"unrelated smithy code", &fakeAPIError{code: "ThrottlingException"}, false},
		{"wrapped AccessDenied", fmt.Errorf("list amplify apps: %w", &fakeAPIError{code: "AccessDeniedException"}), true},
		{"region unsupported - no such host", errors.New("dial tcp: lookup amplify.eu-south-1.amazonaws.com: no such host"), true},
		{"region unsupported - resolve endpoint", errors.New("could not resolve endpoint"), true},
		{"region unsupported - EndpointNotFound", errors.New("EndpointNotFound for service in region"), true},
		{"plain unrelated error", errors.New("network connection refused"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsSkippableAWSError(tc.err))
		})
	}
}

func TestSkipReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"smithy code", &fakeAPIError{code: "AccessDeniedException"}, "AccessDeniedException"},
		{"wrapped smithy code", fmt.Errorf("ctx: %w", &fakeAPIError{code: "OptInRequired"}), "OptInRequired"},
		{"region unsupported", errors.New("no such host"), "RegionUnsupported"},
		{"unknown", errors.New("something else"), "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SkipReason(tc.err))
		})
	}
}
