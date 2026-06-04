package enumeration

import (
	"errors"
	"strings"

	smithy "github.com/aws/smithy-go"
)

// fatalErrorCodes lists smithy/AWS error codes that should NOT be skipped —
// these indicate a fundamental problem that will affect all subsequent calls
// (bad credentials, expired token, etc.). Everything else is skippable.
//
// Design decision: denylist (fatal codes) rather than allowlist (skippable codes).
//
// A false-positive skip loses one resource type in one region — bounded,
// observable in the skip summary and enumeration-skips.json. A false-positive
// fatal aborts the entire pipeline — unbounded, loses all remaining work.
//
// AWS services invent new error codes frequently. An allowlist requires a
// code change for each new skippable code; with Guard's version promotion
// cadence, that's a multi-day coverage gap per new code. A denylist only
// grows for genuinely fatal codes (credential/signature failures), which
// are rare and well-defined.
//
// Transient errors (InternalServerError, ServiceUnavailableException) are
// NOT in this list because the SDK's adaptive retry mode already handles
// them. By the time they reach IsSkippableAWSError, retries are exhausted
// and the error is terminal for that call. Skipping is correct — these
// are per-call failures, not credential-level failures.
//
// Every skip is observable: Debug log per skip, Warn summary (always prints,
// grouped by service/operation with per-code counts), and full detail in
// enumeration-skips.json. An operator can distinguish ValidationException×3
// from AccessDeniedException×45 at a glance.
//
// Known gap: when running inside Guard, the consumer may not read the skip
// report. Surfacing partial coverage to the security conclusion is a product
// concern tracked separately.
// DO NOT modify after init — read concurrently from multiple goroutines.
// The only permitted mutation is in skiperror_fatal_test_mode.go's init().
var fatalErrorCodes = map[string]struct{}{
	"ExpiredToken":               {},
	"ExpiredTokenException":      {},
	"RequestExpired":             {},
	"SignatureDoesNotMatch":      {},
	"IncompleteSignature":        {},
	"MissingAuthenticationToken": {},
	"InvalidClientTokenId":       {},
}

// IsSkippableAWSError reports whether the error is a per-(region, service)
// failure that should be recorded and skipped rather than aborting the
// pipeline. All AWS API errors are skippable by default except fatal
// credential/signature errors that would affect every subsequent call.
//
// Note: this includes ThrottlingException. Throttling is a transient,
// per-call condition — the SDK's adaptive retry mode (configured in
// internal/helpers/aws.NewAWSConfig) handles retry automatically. If
// retries are exhausted and the call still throttles, we record it as a
// skip rather than aborting the entire pipeline. Retry/backoff policy
// belongs in the rate-limiting layer (pkg/ratelimit), not here.
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
