package enumeration

import (
	"errors"
	"strings"

	smithy "github.com/aws/smithy-go"
)

// skippableErrorCodes lists smithy/AWS error codes that indicate a single
// (region, service) call should be skipped rather than failing the whole
// enumeration run. Covers SCP explicit denies, missing permissions, opt-in
// regions, and CloudControl type-not-supported responses.
var skippableErrorCodes = map[string]struct{}{
	"AccessDenied":                {},
	"AccessDeniedException":       {},
	"UnauthorizedOperation":       {},
	"AuthFailure":                 {},
	"OptInRequired":               {},
	"InvalidClientTokenId":        {},
	"UnrecognizedClientException": {},
	"TypeNotFoundException":       {},
	"UnsupportedActionException":  {},
}

// IsSkippableAWSError reports whether the error is a non-fatal AWS API failure
// for a single (region, service) call: a known auth/opt-in/type code, or a
// DNS/endpoint resolution failure indicating the service is unavailable in the
// region.
func IsSkippableAWSError(err error) bool {
	if err == nil {
		return false
	}
	if code, ok := extractAPIErrorCode(err); ok {
		if _, found := skippableErrorCodes[code]; found {
			return true
		}
	}
	return isRegionUnsupportedError(err)
}

// SkipReason returns the smithy error code if the error has one, otherwise
// "RegionUnsupported" for DNS/endpoint failures, or "Unknown" for any other
// non-coded error. Caller is expected to use this only after IsSkippableAWSError.
func SkipReason(err error) string {
	if err == nil {
		return ""
	}
	if code, ok := extractAPIErrorCode(err); ok {
		return code
	}
	if isRegionUnsupportedError(err) {
		return "RegionUnsupported"
	}
	return "Unknown"
}

// extractAPIErrorCode unwraps err looking for a smithy.APIError and returns
// (code, true) only when a non-empty smithy error code is present.
func extractAPIErrorCode(err error) (string, bool) {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code, code != ""
	}
	return "", false
}

// isRegionUnsupportedError returns true when the error indicates the AWS
// service is not available in the target region (DNS resolution failure or
// explicit region-not-supported response). These errors aren't smithy-coded,
// so substring matching is the only signal available.
//
// The "no such host" check is scoped to AWS endpoint DNS names
// (*.amazonaws.com) to avoid masking transient DNS failures on non-AWS hosts.
func isRegionUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "could not resolve endpoint") ||
		strings.Contains(msg, "EndpointNotFound") {
		return true
	}
	// Only treat "no such host" as region-unsupported when the failing
	// lookup is for an AWS service endpoint, not an arbitrary hostname.
	if strings.Contains(msg, "no such host") && strings.Contains(msg, ".amazonaws.com") {
		return true
	}
	return false
}
