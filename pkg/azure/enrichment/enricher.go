package enrichment

import (
	"context"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// AzureConfigEnricher runs registered enricher functions on ARG query results.
// Templates without registered enrichers pass through unchanged.
// Templates with enrichers are confirmed or dropped based on SDK API calls.
type AzureConfigEnricher struct {
	ctx  context.Context
	cred azcore.TokenCredential
}

// NewAzureConfigEnricher creates an enricher with the given context and credentials.
func NewAzureConfigEnricher(ctx context.Context, cred azcore.TokenCredential) *AzureConfigEnricher {
	return &AzureConfigEnricher{ctx: ctx, cred: cred}
}

// Enrich is a pipeline-compatible method that looks up registered enrichers
// for the result's template ID, runs each one, and gates on the result.
func (e *AzureConfigEnricher) Enrich(result templates.ARGQueryResult, out *pipeline.P[templates.ARGQueryResult]) error {
	enrichers := plugin.GetAzureEnrichers(result.TemplateID)
	if len(enrichers) == 0 {
		out.Send(result)
		return nil
	}

	cfg := plugin.AzureEnricherConfig{
		Context:    e.ctx,
		Credential: e.cred,
	}
	for _, enrich := range enrichers {
		confirmed, err := enrich(cfg, result)
		if err != nil {
			slog.Warn("azure enricher failed, dropping candidate",
				"template", result.TemplateID, "resource", result.ResourceID, "error", err)
			return nil
		}
		if !confirmed {
			return nil
		}
	}
	out.Send(result)
	return nil
}
