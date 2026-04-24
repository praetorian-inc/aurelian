package enumeration

import (
	"errors"
	"log/slog"
	"strings"

	smithy "github.com/aws/smithy-go"
)

// isAccessDeniedError reports whether err is an AWS access-denied response
// (including IAM denials and SCP explicit denies). Callers treat these as a
// warning so a single deny doesn't abort enumeration across other regions or
// resource types.
func isAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "AccessDenied", "UnauthorizedOperation":
			return true
		}
	}
	s := err.Error()
	return strings.Contains(s, "AccessDeniedException") ||
		strings.Contains(s, "UnauthorizedOperation") ||
		strings.Contains(s, "is not authorized to perform")
}

// isUnsupportedTypeError reports whether err indicates the resource type or
// action is not supported in this region (CloudControl-specific).
func isUnsupportedTypeError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "TypeNotFoundException", "UnsupportedActionException":
			return true
		}
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException")
}

// isRegionUnsupportedError reports whether err indicates the AWS service is
// not available in the target region (DNS resolution failure or explicit
// region-not-supported response).
func isRegionUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "could not resolve endpoint") ||
		strings.Contains(msg, "EndpointNotFound")
}

// handleListError classifies err returned from a per-region list call and
// decides whether enumeration for other regions / resource types should
// continue. It returns nil (logging at the appropriate level) if the error is
// a known per-region condition, or the original error if enumeration should
// abort.
//
//   - Region not available → Debug, continue (routine, some services are
//     missing from some regions).
//   - Unsupported resource type / action → Debug, continue (CloudControl only).
//   - Access denied (IAM or SCP) → Warn, continue (the user sees why a region
//     or service produced no data).
//   - Anything else → returned as-is; caller decides whether to abort.
func handleListError(err error, resourceType, region string) error {
	if err == nil {
		return nil
	}
	if isRegionUnsupportedError(err) {
		slog.Debug("service not available in region, skipping",
			"type", resourceType, "region", region)
		return nil
	}
	if isUnsupportedTypeError(err) {
		slog.Debug("resource type not supported, skipping",
			"type", resourceType, "region", region)
		return nil
	}
	if isAccessDeniedError(err) {
		slog.Warn("access denied listing resources, skipping",
			"type", resourceType, "region", region, "error", err)
		return nil
	}
	return err
}
