package plugin

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/templates"
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

// --- Azure Enricher Registry ---

// AzureEnricherConfig provides context and credentials for Azure enrichers.
type AzureEnricherConfig struct {
	Context    context.Context
	Credential azcore.TokenCredential
}

// AzureEnrichmentCommand represents a triage command produced by an enricher.
type AzureEnrichmentCommand struct {
	Command                   string `json:"command"`
	Description               string `json:"description"`
	ExpectedOutputDescription string `json:"expected_output_description"`
	ActualOutput              string `json:"actual_output"`
	ExitCode                  int    `json:"exit_code"`
	Error                     string `json:"error,omitempty"`
}

// AzureEnricherFunc enriches an ARG query result and returns triage commands.
type AzureEnricherFunc func(cfg AzureEnricherConfig, result *templates.ARGQueryResult) ([]AzureEnrichmentCommand, error)

type azureEnricherRegistry struct {
	mu        sync.RWMutex
	enrichers map[string][]AzureEnricherFunc
}

var globalAzureEnricherRegistry = &azureEnricherRegistry{
	enrichers: make(map[string][]AzureEnricherFunc),
}

func RegisterAzureEnricher(templateID string, fn AzureEnricherFunc) {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()
	globalAzureEnricherRegistry.enrichers[templateID] = append(
		globalAzureEnricherRegistry.enrichers[templateID], fn,
	)
}

func GetAzureEnrichers(templateID string) []AzureEnricherFunc {
	globalAzureEnricherRegistry.mu.RLock()
	defer globalAzureEnricherRegistry.mu.RUnlock()
	enrichers := globalAzureEnricherRegistry.enrichers[templateID]
	if enrichers == nil {
		return []AzureEnricherFunc{}
	}
	return enrichers
}

func ResetAzureEnricherRegistry() {
	globalAzureEnricherRegistry.mu.Lock()
	defer globalAzureEnricherRegistry.mu.Unlock()
	globalAzureEnricherRegistry.enrichers = make(map[string][]AzureEnricherFunc)
}
