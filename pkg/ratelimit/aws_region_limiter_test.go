package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSRegionLimiter_BasicAcquireRelease(t *testing.T) {
	limiter := NewAWSRegionLimiter(5)

	ctx := context.Background()
	release, err := limiter.Acquire(ctx, "us-east-1")
	require.NoError(t, err)
	assert.NotNil(t, release)

	// Verify slot is taken
	assert.Equal(t, 1, limiter.ActiveCount("us-east-1"))
	assert.Equal(t, 4, limiter.AvailableCount("us-east-1"))

	// Release slot
	release()

	// Verify slot is released
	assert.Equal(t, 0, limiter.ActiveCount("us-east-1"))
	assert.Equal(t, 5, limiter.AvailableCount("us-east-1"))
}

func TestAWSRegionLimiter_ConcurrentAccess(t *testing.T) {
	const maxConcurrent = 5
	const numGoroutines = 20

	limiter := NewAWSRegionLimiter(maxConcurrent)
	ctx := context.Background()

	var current, peak atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			release, err := limiter.Acquire(ctx, "us-west-2")
			require.NoError(t, err)
			defer release()

			// Track concurrent count
			n := current.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}

			time.Sleep(10 * time.Millisecond)
			current.Add(-1)
		}()
	}

	wg.Wait()

	// Peak should never exceed limit
	assert.LessOrEqual(t, int(peak.Load()), maxConcurrent)
	// All slots should be released
	assert.Equal(t, 0, limiter.ActiveCount("us-west-2"))
}

func TestAWSRegionLimiter_ContextCancellation(t *testing.T) {
	limiter := NewAWSRegionLimiter(1)

	// Fill the semaphore
	ctx1 := context.Background()
	release1, err := limiter.Acquire(ctx1, "eu-west-1")
	require.NoError(t, err)
	defer release1()

	// Try to acquire with canceled context
	ctx2, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	release2, err := limiter.Acquire(ctx2, "eu-west-1")
	assert.Error(t, err)
	assert.Nil(t, release2)
	assert.Equal(t, context.Canceled, err)
}

func TestAWSRegionLimiter_TryAcquire_Available(t *testing.T) {
	limiter := NewAWSRegionLimiter(5)

	release, ok := limiter.TryAcquire("ap-south-1")
	assert.True(t, ok)
	assert.NotNil(t, release)

	assert.Equal(t, 1, limiter.ActiveCount("ap-south-1"))
	release()
	assert.Equal(t, 0, limiter.ActiveCount("ap-south-1"))
}

func TestAWSRegionLimiter_TryAcquire_Full(t *testing.T) {
	limiter := NewAWSRegionLimiter(2)
	ctx := context.Background()

	// Fill all slots
	release1, err := limiter.Acquire(ctx, "ap-northeast-1")
	require.NoError(t, err)
	defer release1()

	release2, err := limiter.Acquire(ctx, "ap-northeast-1")
	require.NoError(t, err)
	defer release2()

	// TryAcquire should fail
	release3, ok := limiter.TryAcquire("ap-northeast-1")
	assert.False(t, ok)
	assert.Nil(t, release3)
}

func TestAWSRegionLimiter_MultipleRegions(t *testing.T) {
	limiter := NewAWSRegionLimiter(3)
	ctx := context.Background()

	// Acquire slots in different regions
	release1, err := limiter.Acquire(ctx, "us-east-1")
	require.NoError(t, err)
	defer release1()

	release2, err := limiter.Acquire(ctx, "us-west-2")
	require.NoError(t, err)
	defer release2()

	release3, err := limiter.Acquire(ctx, "eu-central-1")
	require.NoError(t, err)
	defer release3()

	// Each region should have 1 active
	assert.Equal(t, 1, limiter.ActiveCount("us-east-1"))
	assert.Equal(t, 1, limiter.ActiveCount("us-west-2"))
	assert.Equal(t, 1, limiter.ActiveCount("eu-central-1"))

	// Regions don't interfere
	release4, err := limiter.Acquire(ctx, "us-east-1")
	require.NoError(t, err)
	defer release4()

	assert.Equal(t, 2, limiter.ActiveCount("us-east-1"))
	assert.Equal(t, 1, limiter.ActiveCount("us-west-2"))
}

func TestAWSRegionLimiter_Stats(t *testing.T) {
	limiter := NewAWSRegionLimiter(5)
	ctx := context.Background()

	// Initial state - no regions
	stats := limiter.Stats()
	assert.Empty(t, stats)

	// Acquire in multiple regions
	release1, err := limiter.Acquire(ctx, "us-east-1")
	require.NoError(t, err)
	defer release1()

	release2, err := limiter.Acquire(ctx, "us-east-1")
	require.NoError(t, err)
	defer release2()

	release3, err := limiter.Acquire(ctx, "eu-west-1")
	require.NoError(t, err)
	defer release3()

	// Check stats
	stats = limiter.Stats()
	assert.Equal(t, 2, stats["us-east-1"])
	assert.Equal(t, 1, stats["eu-west-1"])
}

func TestAWSRegionLimiter_AcquireWithTimeout(t *testing.T) {
	limiter := NewAWSRegionLimiter(1)

	// Fill the slot
	ctx1 := context.Background()
	release1, err := limiter.Acquire(ctx1, "us-east-1")
	require.NoError(t, err)
	defer release1()

	// Try to acquire with timeout
	ctx2 := context.Background()
	release2, err := limiter.AcquireWithTimeout(ctx2, "us-east-1", 50*time.Millisecond)
	assert.Error(t, err)
	assert.Nil(t, release2)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestAWSRegionLimiter_Limit(t *testing.T) {
	limiter := NewAWSRegionLimiter(7)
	assert.Equal(t, 7, limiter.Limit())
}

func TestAWSRegionLimiter_Global(t *testing.T) {
	// First call creates singleton
	limiter1 := Global()
	assert.NotNil(t, limiter1)

	// Subsequent calls return same instance
	limiter2 := Global()
	assert.Same(t, limiter1, limiter2)

	// Default limit should be 5
	assert.Equal(t, 5, limiter1.Limit())
}
