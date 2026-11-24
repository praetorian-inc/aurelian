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
	Service     string
}

func NewCrossRegionActor(concurrency int) *CrossRegionActor {
	return &CrossRegionActor{Concurrency: concurrency}
}

func NewCrossRegionActorForService(concurrency int, service string) *CrossRegionActor {
	return &CrossRegionActor{Concurrency: concurrency, Service: service}
}

func (c *CrossRegionActor) ActInRegions(regions []string, action func(region string) error) error {
	g := errgroup.Group{}
	g.SetLimit(c.concurrencyOrDefault())

	for _, region := range regions {
		g.Go(func() error {
			return c.ActInRegion(region, func() error {
				return action(region)
			})
		})
	}

	return g.Wait()
}

func (c *CrossRegionActor) ActInRegion(region string, action func() error) error {
	limiter := c.getLimiter(region)
	release, err := limiter.Acquire(context.Background(), region)
	if err != nil {
		return err
	}
	defer release()
	return action()
}

func (c *CrossRegionActor) limiterKey(region string) string {
	return region + "\x00" + c.Service
}

func (c *CrossRegionActor) getLimiter(region string) *AWSRegionLimiter {
	key := c.limiterKey(region)
	concurrency := c.concurrencyOrDefault()

	crossRegionLimitersMu.RLock()
	limiter, ok := crossRegionLimiters[key]
	crossRegionLimitersMu.RUnlock()
	if ok {
		return limiter
	}

	crossRegionLimitersMu.Lock()
	defer crossRegionLimitersMu.Unlock()
	if limiter, ok = crossRegionLimiters[key]; ok {
		return limiter
	}

	limiter = NewAWSRegionLimiter(concurrency)
	crossRegionLimiters[key] = limiter
	return limiter
}

func (c *CrossRegionActor) concurrencyOrDefault() int {
	if c.Concurrency <= 0 {
		return 1
	}
	return c.Concurrency
}
