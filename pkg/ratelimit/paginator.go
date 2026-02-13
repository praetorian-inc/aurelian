package ratelimit

import (
	"strings"
	"time"
)

type Paginator struct {
	ShouldRetry func(error) bool
	Backoff     func(retryAttempt int)
	MaxAttempts int
}

func NewPaginator() *Paginator {
	return &Paginator{
		ShouldRetry: defaultShouldRetry,
		MaxAttempts: 5,
	}
}

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
	time.Sleep(5 * time.Duration(1<<retryAttempt))
}

func (p *Paginator) maxAttemptsOrDefault() int {
	if p.MaxAttempts <= 0 {
		return 5
	}
	return p.MaxAttempts
}

func defaultShouldRetry(err error) bool {
	return strings.Contains(err.Error(), "ThrottlingException: Rate exceeded")
}
