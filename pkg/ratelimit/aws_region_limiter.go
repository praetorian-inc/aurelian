// Package ratelimit provides global per-region rate limiting for AWS API calls.
//
// This prevents AWS API throttling by limiting concurrent calls per region.
// AWS services often have per-region API rate limits, and exceeding these limits
// can cause throttling errors that slow down or fail operations.
//
// Example usage:
//
//	limiter := ratelimit.Global()
//	release, err := limiter.Acquire(ctx, "us-east-1")
//	if err != nil {
//	    return err // context cancelled
//	}
//	defer release()
//	// ... make AWS API calls ...
package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

var (
	globalLimiter *AWSRegionLimiter
	once          sync.Once
)

// regionState tracks the semaphore and active count for a region.
type regionState struct {
	sem    *semaphore.Weighted
	active int64 // atomic counter for active slots
}

// AWSRegionLimiter enforces per-region concurrency limits for AWS API calls.
// Each region gets its own semaphore to prevent cross-region interference.
type AWSRegionLimiter struct {
	limit   int
	regions map[string]*regionState
	mu      sync.RWMutex
}

// NewAWSRegionLimiter creates a new rate limiter with the specified per-region limit.
// The limit applies independently to each AWS region.
func NewAWSRegionLimiter(limit int) *AWSRegionLimiter {
	return &AWSRegionLimiter{
		limit:   limit,
		regions: make(map[string]*regionState),
	}
}

// Global returns the global singleton AWSRegionLimiter with default limit of 5 per region.
// Subsequent calls return the same instance.
func Global() *AWSRegionLimiter {
	once.Do(func() {
		globalLimiter = NewAWSRegionLimiter(5)
	})
	return globalLimiter
}

// getOrCreateRegionState returns the region state, creating it if needed.
// Uses double-checked locking pattern for performance.
func (l *AWSRegionLimiter) getOrCreateRegionState(region string) *regionState {
	// Fast path: region already exists
	l.mu.RLock()
	state, ok := l.regions[region]
	l.mu.RUnlock()
	if ok {
		return state
	}

	// Slow path: create region state
	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check: another goroutine might have created it
	if state, ok := l.regions[region]; ok {
		return state
	}

	state = &regionState{
		sem:    semaphore.NewWeighted(int64(l.limit)),
		active: 0,
	}
	l.regions[region] = state
	return state
}

// Acquire blocks until a slot is available for the specified region.
// Returns a release function that must be called when done, and an error if context is cancelled.
//
// Example:
//
//	release, err := limiter.Acquire(ctx, "us-east-1")
//	if err != nil {
//	    return err
//	}
//	defer release()
func (l *AWSRegionLimiter) Acquire(ctx context.Context, region string) (release func(), err error) {
	state := l.getOrCreateRegionState(region)

	if err := state.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}

	atomic.AddInt64(&state.active, 1)

	return func() {
		atomic.AddInt64(&state.active, -1)
		state.sem.Release(1)
	}, nil
}

// TryAcquire attempts to acquire a slot without blocking.
// Returns a release function and true if successful, nil and false if no slots available.
func (l *AWSRegionLimiter) TryAcquire(region string) (release func(), ok bool) {
	state := l.getOrCreateRegionState(region)

	if !state.sem.TryAcquire(1) {
		return nil, false
	}

	atomic.AddInt64(&state.active, 1)

	return func() {
		atomic.AddInt64(&state.active, -1)
		state.sem.Release(1)
	}, true
}

// AcquireWithTimeout attempts to acquire a slot with a timeout.
// Returns a release function if successful, or an error if timeout expires or context is cancelled.
func (l *AWSRegionLimiter) AcquireWithTimeout(ctx context.Context, region string, timeout time.Duration) (release func(), err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return l.Acquire(ctx, region)
}

// ActiveCount returns the number of currently active slots for a region.
// Returns 0 if the region has never been used.
func (l *AWSRegionLimiter) ActiveCount(region string) int {
	l.mu.RLock()
	state, ok := l.regions[region]
	l.mu.RUnlock()

	if !ok {
		return 0
	}

	return int(atomic.LoadInt64(&state.active))
}

// AvailableCount returns the number of available slots for a region.
// Returns the full limit if the region has never been used.
func (l *AWSRegionLimiter) AvailableCount(region string) int {
	active := l.ActiveCount(region)
	return l.limit - active
}

// Stats returns a map of region names to their current active slot count.
// Only includes regions that have been used.
func (l *AWSRegionLimiter) Stats() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := make(map[string]int, len(l.regions))
	for region := range l.regions {
		stats[region] = l.ActiveCount(region)
	}

	return stats
}

// Limit returns the configured per-region limit.
func (l *AWSRegionLimiter) Limit() int {
	return l.limit
}
