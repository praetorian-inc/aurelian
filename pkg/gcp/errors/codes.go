package errors

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsPermissionDenied checks if an error is a permission denied error.
// This occurs when the authenticated user/service account lacks required IAM permissions.
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}

	// Check gRPC status code
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.PermissionDenied {
		return true
	}

	// Fallback: check error message
	errMsg := err.Error()
	return strings.Contains(errMsg, "PermissionDenied") ||
		strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "does not have") ||
		strings.Contains(errMsg, "AccessDeniedException")
}

// IsServiceDisabled checks if an error indicates a GCP API service is disabled.
// This typically means the API needs to be enabled in the GCP project.
func IsServiceDisabled(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()
	return strings.Contains(errMsg, "SERVICE_DISABLED") ||
		strings.Contains(errMsg, "service") && strings.Contains(errMsg, "disabled") ||
		strings.Contains(errMsg, "API has not been enabled") ||
		strings.Contains(errMsg, "API has not been used in project") ||
		strings.Contains(errMsg, "Access Not Configured") ||
		strings.Contains(errMsg, "has not been used") && strings.Contains(errMsg, "before or it is disabled")
}

// IsBillingDisabled checks if an error indicates billing is disabled for the project.
// This means the GCP project doesn't have a billing account attached or billing is inactive.
func IsBillingDisabled(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()
	return strings.Contains(errMsg, "BILLING_DISABLED") ||
		strings.Contains(errMsg, "billing account") && strings.Contains(errMsg, "disabled") ||
		strings.Contains(errMsg, "billing is disabled")
}

// IsNotFound checks if an error indicates a resource was not found.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if ok && st.Code() == codes.NotFound {
		return true
	}

	errMsg := err.Error()
	return strings.Contains(errMsg, "NotFound") ||
		strings.Contains(errMsg, "not found")
}

// IsUnauthenticated checks if an error indicates authentication failure.
func IsUnauthenticated(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if ok && st.Code() == codes.Unauthenticated {
		return true
	}

	errMsg := err.Error()
	return strings.Contains(errMsg, "Unauthenticated") ||
		strings.Contains(errMsg, "authentication") ||
		strings.Contains(errMsg, "invalid credentials")
}
