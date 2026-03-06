package extraction

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

func TestIsPermissionOrNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"random error", errors.New("something broke"), false},
		{"403 Forbidden", &azcore.ResponseError{StatusCode: http.StatusForbidden}, true},
		{"401 Unauthorized", &azcore.ResponseError{StatusCode: http.StatusUnauthorized}, true},
		{"404 NotFound", &azcore.ResponseError{StatusCode: http.StatusNotFound}, true},
		{"429 TooManyRequests", &azcore.ResponseError{StatusCode: http.StatusTooManyRequests}, true},
		{"409 Conflict", &azcore.ResponseError{StatusCode: http.StatusConflict}, false},
		{"wrapped 403", fmt.Errorf("outer: %w", &azcore.ResponseError{StatusCode: http.StatusForbidden}), true},
		{"AuthorizationFailed in message", errors.New("AuthorizationFailed: no authorization"), true},
		{"AuthenticationFailed in message", errors.New("AuthenticationFailed: invalid token"), true},
		{"LinkedAuthorizationFailed in message", errors.New("LinkedAuthorizationFailed: linked scope"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPermissionOrNotFound(tt.err); got != tt.expected {
				t.Errorf("isPermissionOrNotFound() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHandleExtractError(t *testing.T) {
	if err := handleExtractError(&azcore.ResponseError{StatusCode: http.StatusForbidden}, "test", "res"); err != nil {
		t.Errorf("expected nil for 403, got %v", err)
	}
	if err := handleExtractError(&azcore.ResponseError{StatusCode: http.StatusTooManyRequests}, "test", "res"); err != nil {
		t.Errorf("expected nil for 429, got %v", err)
	}
	if err := handleExtractError(errors.New("unexpected"), "test", "res"); err == nil {
		t.Error("expected error for unexpected failure, got nil")
	}
	if err := handleExtractError(nil, "test", "res"); err != nil {
		t.Errorf("expected nil for nil, got %v", err)
	}
}
