package enrichment

import (
	"context"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AzureEnricher runs registered enricher functions on Azure resources.
type AzureEnricher struct {
	cred azcore.TokenCredential
}

// NewAzureEnricher creates an AzureEnricher with the given credential.
func NewAzureEnricher(cred azcore.TokenCredential) *AzureEnricher {
	return &AzureEnricher{cred: cred}
}

// Enrich looks up registered enrichers for the resource's type, runs each,
// and forwards the resource downstream. Enricher errors are logged but never
// propagated — the resource is always forwarded.
func (e *AzureEnricher) Enrich(r output.AzureResource, out *pipeline.P[output.AzureResource]) error {
	enrichers := plugin.GetAzureEnrichers(r.ResourceType)
	if len(enrichers) == 0 {
		out.Send(r)
		return nil
	}

	ecfg := plugin.AzureEnricherConfig{
		Context:    context.Background(),
		Credential: e.cred,
	}
	for _, enrich := range enrichers {
		if err := enrich(ecfg, &r); err != nil {
			slog.Warn("azure enricher failed",
				"type", r.ResourceType,
				"resource", r.ResourceID,
				"error", err)
		}
	}
	out.Send(r)

	return nil
}
