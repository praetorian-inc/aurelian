package ratelimit

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

var (
	crossRegionLimitersMu sync.RWMutex
	crossRegionLimiters   = make(map[string]*AWSRegionLimiter)
)

type CrossRegionActor struct {
	Concurrency int
}

func NewCrossRegionActor(concurrency int) *CrossRegionActor {
	return &CrossRegionActor{Concurrency: concurrency}
}

func (c *CrossRegionActor) ActInRegions(regions []string, action func(region string) error) error {
	g := errgroup.Group{}
	g.SetLimit(c.concurrencyOrDefault())

	for _, region := range regions {
		region := region
		g.Go(func() error {
			limiter := c.getLimiter(region)
			release, err := limiter.Acquire(context.Background(), region)
			if err != nil {
				return err
			}
			defer release()

			return action(region)
		})
	}

	return g.Wait()
}

func (c *CrossRegionActor) getLimiter(region string) *AWSRegionLimiter {
	crossRegionLimitersMu.RLock()
	limiter, ok := crossRegionLimiters[region]
	crossRegionLimitersMu.RUnlock()
	if ok {
		return limiter
	}

	crossRegionLimitersMu.Lock()
	defer crossRegionLimitersMu.Unlock()
	if limiter, ok = crossRegionLimiters[region]; ok {
		return limiter
	}

	limiter = NewAWSRegionLimiter(c.concurrencyOrDefault())
	crossRegionLimiters[region] = limiter
	return limiter
}

func (c *CrossRegionActor) concurrencyOrDefault() int {
	if c.Concurrency <= 0 {
		return 1
	}
	return c.Concurrency
}
