package errors

import (
	"log/slog"
	"time"
)

// simple backoff seems to be better for gcp sliding window
func RetryWithBackoff(fn func() error) error {
	const maxRetries = 4
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !shouldRetry(err) {
			return err
		}
		if attempt < maxRetries {
			delay := calculateBackoffDelay(err, attempt)
			slog.Warn("Quota exceeded, retrying with backoff",
				"attempt", attempt+1,
				"maxRetries", maxRetries,
				"backoffDelay", delay,
				"error", err.Error())
			time.Sleep(delay)
		}
	}
	return err
}

func RetryIterator[T any](next func() (T, error)) (T, error) {
	const maxRetries = 4
	var result T
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, err = next()
		if err == nil {
			return result, nil
		}
		if !shouldRetry(err) {
			return result, err
		}
		if attempt < maxRetries {
			delay := calculateBackoffDelay(err, attempt)
			slog.Warn("Quota exceeded on iterator, retrying with backoff",
				"attempt", attempt+1,
				"maxRetries", maxRetries,
				"backoffDelay", delay,
				"error", err.Error())
			time.Sleep(delay)
		}
	}
	return result, err
}

func calculateBackoffDelay(err error, attempt int) time.Duration {
	if delay := GetRetryInfoDelay(err); delay > 0 {
		return delay
	}
	return backoffDelay(attempt)
}

// simple fixed backoff - 30s, 60s, 90s, 120s
func backoffDelay(attempt int) time.Duration {
	delaySeconds := []int{30, 60, 90, 120}
	index := attempt
	if index >= len(delaySeconds) {
		index = len(delaySeconds) - 1
	}
	return time.Duration(delaySeconds[index]) * time.Second
}
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	return IsResourceExhausted(err)
}
