package gcperrors

import "strings"

// IsDisabledAPI returns true if the error indicates a GCP API is not enabled.
func IsDisabledAPI(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "has not been used") ||
		strings.Contains(msg, "it is disabled") ||
		strings.Contains(msg, "API not enabled") ||
		strings.Contains(msg, "SERVICE_DISABLED")
}

// IsPermissionDenied returns true if the error indicates insufficient permissions.
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not have permission") ||
		strings.Contains(msg, "PERMISSION_DENIED")
}

// IsQuotaExceeded returns true if the error indicates a rate limit or quota issue.
func IsQuotaExceeded(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "RATE_LIMIT_EXCEEDED") ||
		strings.Contains(msg, "QUOTA_EXCEEDED") ||
		strings.Contains(msg, "rateLimitExceeded")
}

// ShouldSkip returns true if the error indicates the resource should be skipped
// (disabled API or permission denied).
func ShouldSkip(err error) bool {
	return IsDisabledAPI(err) || IsPermissionDenied(err)
}
