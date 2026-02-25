package plugin

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

type EnricherConfig struct {
	Context   context.Context
	AWSConfig aws.Config
}

type EnricherFunc func(cfg EnricherConfig, r *output.AWSResource) error

type enricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]EnricherFunc
}

var globalEnricherRegistry = &enricherRegistry{
	enrichers: make(map[string][]EnricherFunc),
}

func RegisterEnricher(resourceType string, fn EnricherFunc) {
	globalEnricherRegistry.mu.Lock()
	defer globalEnricherRegistry.mu.Unlock()

	globalEnricherRegistry.enrichers[resourceType] = append(
		globalEnricherRegistry.enrichers[resourceType],
		fn,
	)
}

func GetEnrichers(resourceType string) []EnricherFunc {
	globalEnricherRegistry.mu.RLock()
	defer globalEnricherRegistry.mu.RUnlock()

	enrichers := globalEnricherRegistry.enrichers[resourceType]
	if enrichers == nil {
		return []EnricherFunc{}
	}
	return enrichers
}

func ResetEnricherRegistry() {
	globalEnricherRegistry.mu.Lock()
	defer globalEnricherRegistry.mu.Unlock()

	globalEnricherRegistry.enrichers = make(map[string][]EnricherFunc)
}
