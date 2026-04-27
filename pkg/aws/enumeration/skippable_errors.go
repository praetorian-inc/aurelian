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

// fallbackFn is invoked by handleListError when the primary list call returned
// an AccessDenied response and the call site opted into a fallback. It must
// return nil on success, errFallbackExhausted on expected failure (fallback
// tried but produced nothing), or any other error to propagate as-is.
type fallbackFn func() error

// errFallbackExhausted is the sentinel a fallbackFn returns when the fallback
// path ran to completion but could not produce resources (Config denied, no
// recorder, or CloudControl GetResource denied).
var errFallbackExhausted = errors.New("fallback exhausted")

// handleListError classifies err returned from a per-region list call and
// decides whether enumeration for other regions / resource types should
// continue. When err is AccessDenied and a fallback is supplied, the fallback
// is invoked; the returned behavior is:
//
//   - Region not available → Debug, return nil.
//   - Unsupported resource type → Debug, return nil (CloudControl only).
//   - Access denied with fallback == nil → Warn, return nil (PR #178 behavior).
//   - Access denied with fallback returning nil → Debug, return nil.
//   - Access denied with fallback returning errFallbackExhausted → Warn
//     "unable to list resources" with both primary and fallback errors, return nil.
//   - Access denied with fallback returning any other error → return that error.
//   - Anything else → return err as-is.
func handleListError(err error, resourceType, region string, fallback fallbackFn) error {
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
		if fallback == nil {
			slog.Warn("access denied listing resources, skipping",
				"type", resourceType, "region", region, "error", err)
			return nil
		}
		fbErr := fallback()
		switch {
		case fbErr == nil:
			slog.Debug("fell back to config, listed resources",
				"type", resourceType, "region", region)
			return nil
		case errors.Is(fbErr, errFallbackExhausted):
			slog.Warn("unable to list resources",
				"type", resourceType,
				"region", region,
				"primary", err,
				"fallback", fbErr,
			)
			return nil
		default:
			return fbErr
		}
	}
	return err
}
