package enrichment

import (
	"context"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// AzureEnricher runs registered enricher functions on Azure ARG query results,
// adding enrichment commands and suppressing false positives.
type AzureEnricher struct {
	cred azcore.TokenCredential
}

// NewAzureEnricher creates an AzureEnricher with the given credential.
func NewAzureEnricher(cred azcore.TokenCredential) *AzureEnricher {
	return &AzureEnricher{cred: cred}
}

// Enrich is a pipeline-compatible method that looks up registered enrichers
// for the result's templateID, runs each enricher, attaches enrichment commands,
// and suppresses false positives.
func (e *AzureEnricher) Enrich(result templates.ARGQueryResult, out *pipeline.P[templates.ARGQueryResult]) error {
	enrichers := plugin.GetAzureEnrichers(result.TemplateID)
	if len(enrichers) > 0 {
		cfg := plugin.AzureEnricherConfig{
			Context:    context.Background(),
			Credential: e.cred,
		}

		var allCommands []plugin.AzureEnrichmentCommand
		for _, fn := range enrichers {
			commands, err := fn(cfg, &result)
			if err != nil {
				slog.Warn("enricher failed", "template", result.TemplateID, "resource", result.ResourceID, "error", err)
				continue
			}
			allCommands = append(allCommands, commands...)
		}
		if len(allCommands) > 0 {
			if result.Properties == nil {
				result.Properties = make(map[string]interface{})
			}
			result.Properties["enrichmentCommands"] = allCommands
		}
	}

	if result.Suppressed {
		slog.Info("suppressed false positive", "template", result.TemplateID, "resource", result.ResourceID, "reason", result.SuppressReason)
		return nil
	}

	out.Send(result)
	return nil
}
