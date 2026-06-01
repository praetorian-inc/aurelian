package enumeration

import (
	"errors"
	"strings"

	smithy "github.com/aws/smithy-go"
)

// fatalErrorCodes lists smithy/AWS error codes that should NOT be skipped —
// these indicate a fundamental problem that will affect all subsequent calls
// (bad credentials, expired token, etc.). Everything else is skippable.
var fatalErrorCodes = map[string]struct{}{
	"ExpiredToken":            {},
	"ExpiredTokenException":   {},
	"RequestExpired":          {},
	"SignatureDoesNotMatch":   {},
	"IncompleteSignature":     {},
	"MissingAuthenticationToken": {},
}

// IsSkippableAWSError reports whether the error is a per-(region, service)
// failure that should be recorded and skipped rather than aborting the
// pipeline. All AWS API errors are skippable by default except fatal
// credential/signature errors that would affect every subsequent call.
//
// Note: this includes ThrottlingException. Throttling is a transient,
// per-call condition — the SDK's adaptive retry mode (configured in
// NewAWSConfig) handles retry automatically. If retries are exhausted and
// the call still throttles, we record it as a skip rather than aborting
// the entire pipeline. Retry/backoff policy belongs in the rate-limiting
// layer (pkg/ratelimit), not in the error classifier.
func IsSkippableAWSError(err error) bool {
	if err == nil {
		return false
	}
	if code, ok := extractAPIErrorCode(err); ok {
		if _, fatal := fatalErrorCodes[code]; fatal {
			return false
		}
		return true
	}
	// Non-smithy errors: DNS/endpoint failures are skippable,
	// everything else is not (could be a Go-level network failure,
	// context cancellation, etc.).
	return isRegionUnsupportedError(err)
}

// SkipReason returns a human-readable reason for the skip. For smithy errors
// it returns the error code; for DNS failures "RegionUnsupported"; otherwise
// "Unknown".
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
