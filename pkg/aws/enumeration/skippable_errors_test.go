package enumeration

import (
	"errors"
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
)

func TestIsAccessDeniedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("connection reset"), false},
		{
			"smithy AccessDeniedException",
			&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no perms"},
			true,
		},
		{
			"smithy AccessDenied",
			&smithy.GenericAPIError{Code: "AccessDenied", Message: "no perms"},
			true,
		},
		{
			"smithy UnauthorizedOperation",
			&smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "no perms"},
			true,
		},
		{
			"wrapped smithy AccessDeniedException",
			fmt.Errorf("list apps: %w", &smithy.GenericAPIError{Code: "AccessDeniedException"}),
			true,
		},
		{
			"substring AccessDeniedException (non-smithy)",
			errors.New("operation error Amplify: ListApps, ... api error AccessDeniedException: explicit deny"),
			true,
		},
		{
			"not authorized phrase",
			errors.New("User: arn:aws:... is not authorized to perform: amplify:ListApps"),
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isAccessDeniedError(tc.err))
		})
	}
}

func TestIsUnsupportedTypeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("boom"), false},
		{
			"smithy TypeNotFoundException",
			&smithy.GenericAPIError{Code: "TypeNotFoundException"},
			true,
		},
		{
			"smithy UnsupportedActionException",
			&smithy.GenericAPIError{Code: "UnsupportedActionException"},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isUnsupportedTypeError(tc.err))
		})
	}
}

func TestIsRegionUnsupportedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("boom"), false},
		{"no such host", errors.New("dial tcp: lookup amplify.zz-weird-1.amazonaws.com: no such host"), true},
		{"could not resolve endpoint", errors.New("could not resolve endpoint: bad region"), true},
		{"EndpointNotFound", errors.New("EndpointNotFound: region not available"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isRegionUnsupportedError(tc.err))
		})
	}
}

func TestHandleListError_NilReturnsNil(t *testing.T) {
	assert.NoError(t, handleListError(nil, "AWS::Amplify::App", "us-east-1", nil))
}

func TestHandleListError_SkipsAccessDenied(t *testing.T) {
	err := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "explicit deny"}
	assert.NoError(t, handleListError(err, "AWS::Amplify::App", "ap-northeast-1", nil))
}

func TestHandleListError_SkipsRegionUnsupported(t *testing.T) {
	err := errors.New("dial tcp: lookup amplify.zz-weird-1.amazonaws.com: no such host")
	assert.NoError(t, handleListError(err, "AWS::Amplify::App", "zz-weird-1", nil))
}

func TestHandleListError_SkipsUnsupportedType(t *testing.T) {
	err := &smithy.GenericAPIError{Code: "TypeNotFoundException"}
	assert.NoError(t, handleListError(err, "AWS::Some::Type", "us-east-1", nil))
}

func TestHandleListError_PropagatesOtherErrors(t *testing.T) {
	err := errors.New("throttled: retry later")
	got := handleListError(err, "AWS::Amplify::App", "us-east-1", nil)
	assert.ErrorIs(t, got, err)
}

func TestHandleListError_NilFallbackPreservesWarnAndSkip(t *testing.T) {
	// PR #178 behavior: AccessDenied + nil fallback → Warn + skip, return nil.
	err := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "scp"}
	got := handleListError(err, "AWS::Amplify::App", "us-east-1", nil)
	assert.NoError(t, got)
}

func TestHandleListError_FallbackSuccessReturnsNil(t *testing.T) {
	err := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "scp"}
	called := false
	fb := func() error { called = true; return nil }

	got := handleListError(err, "AWS::Amplify::App", "us-east-1", fb)
	assert.NoError(t, got)
	assert.True(t, called, "fallback must be invoked on AccessDenied")
}

func TestHandleListError_FallbackExhaustedWarnsAndReturnsNil(t *testing.T) {
	primary := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "scp"}
	fallback := errFallbackExhausted
	fb := func() error { return fallback }

	got := handleListError(primary, "AWS::Amplify::App", "us-east-1", fb)
	assert.NoError(t, got)
}

func TestHandleListError_FallbackUnexpectedErrorPropagates(t *testing.T) {
	primary := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "scp"}
	boom := errors.New("fallback bug")
	fb := func() error { return boom }

	got := handleListError(primary, "AWS::Amplify::App", "us-east-1", fb)
	assert.ErrorIs(t, got, boom)
}

func TestHandleListError_NonAccessDeniedIgnoresFallback(t *testing.T) {
	err := errors.New("throttled")
	called := false
	fb := func() error { called = true; return nil }

	got := handleListError(err, "AWS::Amplify::App", "us-east-1", fb)
	assert.ErrorIs(t, got, err)
	assert.False(t, called, "fallback must only fire on AccessDenied")
}
