package plugin

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// AzureEnricherConfig holds context and credentials for Azure enrichers.
type AzureEnricherConfig struct {
	Context    context.Context
	Credential azcore.TokenCredential
}

// AzureEnricherFunc enriches an AzureResource in-place.
type AzureEnricherFunc func(cfg AzureEnricherConfig, r *output.AzureResource) error

type azureEnricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]AzureEnricherFunc
}

var globalAzureEnricherRegistry = &azureEnricherRegistry{
	enrichers: make(map[string][]AzureEnricherFunc),
}

// RegisterAzureEnricher registers an enricher for a given Azure resource type.
func RegisterAzureEnricher(resourceType string, fn AzureEnricherFunc) {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()

	globalAzureEnricherRegistry.enrichers[resourceType] = append(
		globalAzureEnricherRegistry.enrichers[resourceType],
		fn,
	)
}

// GetAzureEnrichers returns all registered enrichers for the given Azure resource type.
func GetAzureEnrichers(resourceType string) []AzureEnricherFunc {
	globalAzureEnricherRegistry.mu.RLock()
	defer globalAzureEnricherRegistry.mu.RUnlock()

	enrichers := globalAzureEnricherRegistry.enrichers[resourceType]
	if enrichers == nil {
		return []AzureEnricherFunc{}
	}
	return enrichers
}

// ResetAzureEnricherRegistry clears all registered Azure enrichers. Test utility.
func ResetAzureEnricherRegistry() {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()

	globalAzureEnricherRegistry.enrichers = make(map[string][]AzureEnricherFunc)
}
