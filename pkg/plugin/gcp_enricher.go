package plugin

import (
	"context"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"google.golang.org/api/option"
)

type GCPEnricherConfig struct {
	Context       context.Context
	ClientOptions []option.ClientOption
}

type GCPEnricherFunc func(cfg GCPEnricherConfig, r *output.GCPResource) error

type gcpEnricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]GCPEnricherFunc
}

var globalGCPEnricherRegistry = &gcpEnricherRegistry{
	enrichers: make(map[string][]GCPEnricherFunc),
}

func RegisterGCPEnricher(resourceType string, fn GCPEnricherFunc) {
	globalGCPEnricherRegistry.mu.Lock()
	defer globalGCPEnricherRegistry.mu.Unlock()

	globalGCPEnricherRegistry.enrichers[resourceType] = append(
		globalGCPEnricherRegistry.enrichers[resourceType], fn,
	)
}

func GetGCPEnrichers(resourceType string) []GCPEnricherFunc {
	globalGCPEnricherRegistry.mu.RLock()
	defer globalGCPEnricherRegistry.mu.RUnlock()

	enrichers := globalGCPEnricherRegistry.enrichers[resourceType]
	if enrichers == nil {
		return []GCPEnricherFunc{}
	}
	return enrichers
}

func ResetGCPEnricherRegistry() {
	globalGCPEnricherRegistry.mu.Lock()
	defer globalGCPEnricherRegistry.mu.Unlock()

	globalGCPEnricherRegistry.enrichers = make(map[string][]GCPEnricherFunc)
}
