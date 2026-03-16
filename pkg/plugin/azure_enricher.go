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

// AzureEnricherFunc confirms or drops an ARG query result via Azure SDK API calls.
// Returns (true, nil) to confirm the finding, (false, nil) to drop it.
type AzureEnricherFunc func(cfg AzureEnricherConfig, result templates.ARGQueryResult) (bool, error)

type azureEnricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]AzureEnricherFunc
}

var globalAzureEnricherRegistry = &azureEnricherRegistry{
	enrichers: make(map[string][]AzureEnricherFunc),
}

// RegisterAzureEnricher registers an enricher function for a template ID.
// Called from init() in individual enricher files.
func RegisterAzureEnricher(templateID string, fn AzureEnricherFunc) {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()

	globalAzureEnricherRegistry.enrichers[templateID] = append(
		globalAzureEnricherRegistry.enrichers[templateID], fn,
	)
}

// GetAzureEnrichers returns all enrichers registered for a template ID.
func GetAzureEnrichers(templateID string) []AzureEnricherFunc {
	globalAzureEnricherRegistry.mu.RLock()
	defer globalAzureEnricherRegistry.mu.RUnlock()

	enrichers := globalAzureEnricherRegistry.enrichers[templateID]
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
