package extraction

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// isPermissionOrNotFound returns true if the error indicates a permission denial
// (403/401), a missing resource (404), or Azure throttling (429).
func isPermissionOrNotFound(err error) bool {
	if err == nil {
		return false
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusForbidden, http.StatusUnauthorized,
			http.StatusNotFound, http.StatusTooManyRequests:
			return true
		}
	}

	msg := err.Error()
	for _, keyword := range []string{
		"AuthorizationFailed",
		"AuthenticationFailed",
		"LinkedAuthorizationFailed",
	} {
		if strings.Contains(msg, keyword) {
			return true
		}
	}
	return false
}

// handleExtractError is the standard error handler for all extractors.
// Permission/not-found/throttle errors are logged as warnings and suppressed.
// All other errors are returned to the caller (where the dispatcher catches them).
func handleExtractError(err error, extractorName string, resourceID string) error {
	if err == nil {
		return nil
	}
	if isPermissionOrNotFound(err) {
		slog.Warn("skipping resource (permission denied, not found, or throttled)",
			"extractor", extractorName,
			"resource", resourceID,
			"error", err.Error(),
		)
		return nil
	}
	return err
}
