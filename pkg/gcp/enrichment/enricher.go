package enrichment

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// GCPEnricher runs registered enricher functions on GCP resources.
type GCPEnricher struct {
	opts plugin.GCPCommonRecon
}

// NewGCPEnricher creates a GCPEnricher with the given options.
func NewGCPEnricher(opts plugin.GCPCommonRecon) *GCPEnricher {
	return &GCPEnricher{opts: opts}
}

// Enrich is a pipeline-compatible method that runs registered enrichers.
func (e *GCPEnricher) Enrich(r output.GCPResource, out *pipeline.P[output.GCPResource]) error {
	enrichers := plugin.GetGCPEnrichers(r.ResourceType)
	if len(enrichers) == 0 {
		out.Send(r)
		return nil
	}

	cfg := plugin.GCPEnricherConfig{
		Context:       context.Background(),
		ClientOptions: e.opts.ClientOptions,
	}
	for _, enrich := range enrichers {
		if err := enrich(cfg, &r); err != nil {
			slog.Warn("gcp enricher failed",
				"type", r.ResourceType,
				"resource", r.ResourceID,
				"error", err)
		}
	}
	out.Send(r)
	return nil
}
