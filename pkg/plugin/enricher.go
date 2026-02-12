package plugin

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// EnricherConfig holds pre-resolved auth and context for enrichers.
// Enrich functions receive this instead of handling config loading themselves.
type EnricherConfig struct {
	Context   context.Context
	AWSConfig aws.Config // pre-loaded for the correct region/profile
	// Future: AzureCredential, GCPClient, etc.
}

// EnricherFunc enriches a CloudResource by adding properties in-place.
// Enrichers should be pure logic with no config handling.
// Return nil if enrichment is not applicable (e.g., Lambda with no function URL).
type EnricherFunc func(cfg EnricherConfig, r *output.CloudResource) error

// enricherRegistry stores enricher functions per resource type
type enricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]EnricherFunc // resourceType -> []enricherFunc
}

// globalEnricherRegistry is the package-level registry
var globalEnricherRegistry = &enricherRegistry{
	enrichers: make(map[string][]EnricherFunc),
}

// RegisterEnricher adds an enricher function for a specific resource type.
// Multiple enrichers can be registered for the same resource type - all will run.
// This function is thread-safe and can be called from init() functions.
func RegisterEnricher(resourceType string, fn EnricherFunc) {
	globalEnricherRegistry.mu.Lock()
	defer globalEnricherRegistry.mu.Unlock()

	globalEnricherRegistry.enrichers[resourceType] = append(
		globalEnricherRegistry.enrichers[resourceType],
		fn,
	)
}

// GetEnrichers returns all enricher functions registered for a resource type.
// Returns empty slice if no enrichers are registered.
func GetEnrichers(resourceType string) []EnricherFunc {
	globalEnricherRegistry.mu.RLock()
	defer globalEnricherRegistry.mu.RUnlock()

	enrichers := globalEnricherRegistry.enrichers[resourceType]
	if enrichers == nil {
		return []EnricherFunc{}
	}
	return enrichers
}

// ResetEnricherRegistry clears all registered enrichers (for testing only).
func ResetEnricherRegistry() {
	globalEnricherRegistry.mu.Lock()
	defer globalEnricherRegistry.mu.Unlock()

	globalEnricherRegistry.enrichers = make(map[string][]EnricherFunc)
}
