package enrichment

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// AzureEnricher runs registered enricher functions on ARG query results,
// adding properties not available from Resource Graph. Always forwards results.
type AzureEnricher struct {
	ctx     context.Context
	cred    azcore.TokenCredential
	timeout time.Duration
}

func NewAzureEnricher(ctx context.Context, cred azcore.TokenCredential, timeout time.Duration) *AzureEnricher {
	return &AzureEnricher{ctx: ctx, cred: cred, timeout: timeout}
}

// Enrich is a pipeline-compatible method that looks up registered enrichers
// by resource type, runs each one, and always forwards the result.
func (e *AzureEnricher) Enrich(result templates.ARGQueryResult, out *pipeline.P[templates.ARGQueryResult]) error {
	resourceType := strings.ToLower(result.ResourceType)
	enrichers := plugin.GetAzureEnrichers(resourceType)
	if len(enrichers) == 0 {
		out.Send(result)
		return nil
	}

	if result.Properties == nil {
		result.Properties = make(map[string]any)
	}

	enrichCtx, cancel := context.WithTimeout(e.ctx, e.timeout)
	defer cancel()

	cfg := plugin.AzureEnricherConfig{
		Context:    enrichCtx,
		Credential: e.cred,
	}
	for _, enrich := range enrichers {
		if err := enrich(cfg, &result); err != nil {
			slog.Warn("azure enricher failed",
				"type", result.ResourceType,
				"resource", result.ResourceID,
				"error", err)
		}
	}

	out.Send(result)
	return nil
}
