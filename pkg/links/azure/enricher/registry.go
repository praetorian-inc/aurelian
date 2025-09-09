package enricher

import (
	"context"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// Command represents the input and output of a command that requires manual triage
type Command struct {
	Command                   string `json:"command"`
	Description               string `json:"description"`
	ExpectedOutputDescription string `json:"expected_output_description"`
	ActualOutput              string `json:"actual_output"`
	ExitCode                  int    `json:"exit_code"`
	Error                     string `json:"error,omitempty"`
}

// ResourceEnricher interface for extensible resource enrichment
type ResourceEnricher interface {
	CanEnrich(templateID string) bool
	Enrich(ctx context.Context, resource *model.AzureResource) []Command
}

// EnrichmentRegistry holds all available enrichers
type EnrichmentRegistry struct {
	enrichers []ResourceEnricher
}

// NewEnrichmentRegistry creates a new registry with all available enrichers
func NewEnrichmentRegistry() *EnrichmentRegistry {
	return &EnrichmentRegistry{
		enrichers: []ResourceEnricher{
			// Storage & Data Services
			&StorageAccountEnricher{},
			&CosmosDBEnricher{},
			&RedisCacheEnricher{},
			&SQLServerEnricher{},

			// Web & Application Services
			&VirtualMachineEnricher{},
			&AppServiceEnricher{},
			&ContainerRegistryEnricher{},
			// &AKSClusterEnricher{},

			// Messaging & Event Services
			// &EventHubEnricher{},
			// &ServiceBusEnricher{},
			// &EventGridEnricher{},
			// &DataFactoryEnricher{},

			// Security Services
			&KeyVaultEnricher{},
		},
	}
}

// EnrichResource enriches a resource with security testing commands using all applicable enrichers
func (r *EnrichmentRegistry) EnrichResource(ctx context.Context, templateID string, resource *model.AzureResource) []Command {
	var allCommands []Command

	for _, enricher := range r.enrichers {
		if enricher.CanEnrich(templateID) {
			commands := enricher.Enrich(ctx, resource)
			allCommands = append(allCommands, commands...)
		}
	}

	return allCommands
}
