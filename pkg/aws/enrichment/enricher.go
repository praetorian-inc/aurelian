package enrichment

import (
	"context"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AWSEnricher runs registered enricher functions on AWS resources,
// adding properties not available from CloudControl.
type AWSEnricher struct {
	opts plugin.AWSCommonRecon
}

// NewAWSEnricher creates an AWSEnricher with the given AWS config options.
func NewAWSEnricher(opts plugin.AWSCommonRecon) *AWSEnricher {
	return &AWSEnricher{opts: opts}
}

// Enrich is a pipeline-compatible method that looks up registered enrichers
// for the resource's type, builds a per-region AWS config, runs each enricher,
// and forwards the resource downstream.
func (e *AWSEnricher) Enrich(r output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	enrichers := plugin.GetEnrichers(r.ResourceType)
	if len(enrichers) == 0 {
		out.Send(r)
		return nil
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     r.Region,
		Profile:    e.opts.Profile,
		ProfileDir: e.opts.ProfileDir,
	})
	if err != nil {
		slog.Warn("failed to create AWS config for enrichment, skipping enrichers",
			"resource", r.ResourceID, "region", r.Region, "error", err)
		out.Send(r)
		return nil
	}

	ecfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: awsCfg,
	}
	for _, enrich := range enrichers {
		if err := enrich(ecfg, &r); err != nil {
			slog.Warn("enricher failed",
				"type", r.ResourceType,
				"resource", r.ResourceID,
				"error", err)
		}
	}
	out.Send(r)

	return nil
}
