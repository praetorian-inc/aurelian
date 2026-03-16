package plugin

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// AzureEnricherConfig provides context and credentials to Azure enricher functions.
type AzureEnricherConfig struct {
	Context    context.Context
	Credential azcore.TokenCredential
}

// AzureEnricherFunc adds properties to an ARG query result via Azure SDK API calls.
// Enrichers mutate result.Properties and always return nil on success.
// Errors are logged by the pipeline wrapper; the result is still forwarded.
type AzureEnricherFunc func(cfg AzureEnricherConfig, result *templates.ARGQueryResult) error

type azureEnricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]AzureEnricherFunc
}

var globalAzureEnricherRegistry = &azureEnricherRegistry{
	enrichers: make(map[string][]AzureEnricherFunc),
}

// RegisterAzureEnricher registers an enricher function for a resource type.
// The resourceType should be lowercase (e.g., "microsoft.web/sites").
// Called from init() in individual enricher files.
func RegisterAzureEnricher(resourceType string, fn AzureEnricherFunc) {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()

	globalAzureEnricherRegistry.enrichers[resourceType] = append(
		globalAzureEnricherRegistry.enrichers[resourceType], fn,
	)
}

// GetAzureEnrichers returns all enrichers registered for a resource type.
func GetAzureEnrichers(resourceType string) []AzureEnricherFunc {
	globalAzureEnricherRegistry.mu.RLock()
	defer globalAzureEnricherRegistry.mu.RUnlock()

	enrichers := globalAzureEnricherRegistry.enrichers[resourceType]
	if enrichers == nil {
		return []AzureEnricherFunc{}
	}
	return enrichers
}

// ResetAzureEnricherRegistry clears all registered Azure enrichers. Test utility only.
func ResetAzureEnricherRegistry() {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()

	globalAzureEnricherRegistry.enrichers = make(map[string][]AzureEnricherFunc)
}
