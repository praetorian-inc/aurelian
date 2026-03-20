package ratelimit

import (
	"errors"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"google.golang.org/api/googleapi"
)

// Paginator handles paginated API calls with automatic retry and exponential backoff.
type Paginator struct {
	ShouldRetry func(error) bool
	Backoff     func(retryAttempt int)
	MaxAttempts int
}

// NewAWSPaginator creates a paginator that retries on AWS throttling errors.
func NewAWSPaginator() *Paginator {
	p := newPaginator()
	p.ShouldRetry = func(err error) bool {
		return strings.Contains(err.Error(), "ThrottlingException: Rate exceeded")
	}
	return p
}

// NewGCPPaginator creates a paginator that retries on GCP rate-limit (429)
// and service-unavailable (503) errors.
func NewGCPPaginator() *Paginator {
	p := newPaginator()
	p.ShouldRetry = func(err error) bool {
		if apiErr, ok := err.(*googleapi.Error); ok {
			return apiErr.Code == 429 || apiErr.Code == 503
		}
		return false
	}
	return p
}

// NewAzurePaginator creates a paginator that retries on Azure rate-limit (429)
// and service-unavailable (503) errors.
func NewAzurePaginator() *Paginator {
	p := newPaginator()
	p.ShouldRetry = func(err error) bool {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) {
			return respErr.StatusCode == 429 || respErr.StatusCode == 503
		}
		return false
	}
	return p
}

// newPaginator creates a paginator with no retry policy configured.
func newPaginator() *Paginator {
	return &Paginator{
		MaxAttempts: 5,
	}
}

// Paginate calls action repeatedly until it returns false (no more pages) or
// a non-retryable error. Retryable errors trigger exponential backoff.
func (p *Paginator) Paginate(action func() (bool, error)) error {
	retryAttempt := 0

	for {
		shouldContinue, err := action()
		if err != nil {
			if p.shouldRetry(err) && retryAttempt < p.maxAttemptsOrDefault() {
				p.backoff(retryAttempt)
				retryAttempt++
				continue
			}
			return err
		}

		retryAttempt = 0
		if !shouldContinue {
			return nil
		}
	}
}

func (p *Paginator) shouldRetry(err error) bool {
	if p.ShouldRetry == nil {
		return false
	}
	return p.ShouldRetry(err)
}

func (p *Paginator) backoff(retryAttempt int) {
	if p.Backoff != nil {
		p.Backoff(retryAttempt)
		return
	}
	// default backoff
	time.Sleep(5 * time.Second * time.Duration(1<<retryAttempt))
}

func (p *Paginator) maxAttemptsOrDefault() int {
	if p.MaxAttempts <= 0 {
		return 5
	}
	return p.MaxAttempts
}
