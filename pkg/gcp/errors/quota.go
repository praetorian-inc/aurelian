package errors

import (
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func IsResourceExhausted(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.ResourceExhausted {
		return true
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "ResourceExhausted") || strings.Contains(errMsg, "Quota exceeded") || strings.Contains(errMsg, "RATE_LIMIT_EXCEEDED")
}

func IsQuotaError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	quotaIndicators := []string{
		"quota",
		"rate limit",
		"too many requests",
		"ResourceExhausted",
		"RATE_LIMIT_EXCEEDED",
	}
	errMsgLower := strings.ToLower(errMsg)
	for _, indicator := range quotaIndicators {
		if strings.Contains(errMsgLower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

// extracts retry delay from error's RetryInfo (not always present)
func GetRetryInfoDelay(err error) time.Duration {
	if err == nil {
		return 0
	}
	st, ok := status.FromError(err)
	if !ok {
		return 0
	}
	for _, detail := range st.Details() {
		if retryInfo, ok := detail.(*errdetails.RetryInfo); ok {
			if retryInfo.RetryDelay != nil {
				delay := time.Duration(retryInfo.RetryDelay.Seconds)*time.Second +
					time.Duration(retryInfo.RetryDelay.Nanos)*time.Nanosecond
				return delay
			}
		}
	}
	return 0
}

func GetQuotaMetadata(err error) map[string]string {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		return nil
	}
	for _, detail := range st.Details() {
		if errorInfo, ok := detail.(*errdetails.ErrorInfo); ok {
			if errorInfo.Metadata != nil && len(errorInfo.Metadata) > 0 {
				return errorInfo.Metadata
			}
		}
	}
	return nil
}
