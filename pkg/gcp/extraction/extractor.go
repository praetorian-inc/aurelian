package extraction

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// GCPExtractor extracts scannable content from GCP resources.
type GCPExtractor struct {
	common plugin.GCPCommonRecon
}

// NewGCPExtractor creates an extractor with shared GCP options.
func NewGCPExtractor(common plugin.GCPCommonRecon) *GCPExtractor {
	return &GCPExtractor{common: common}
}

// Extract is a pipeline-compatible method that dispatches by resource type.
func (e *GCPExtractor) Extract(r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	extractors := getExtractors(r.ResourceType)
	if len(extractors) == 0 {
		slog.Debug("no extractor registered for GCP resource type", "type", r.ResourceType)
		return nil
	}

	ctx := extractContext{
		Context:       context.Background(),
		ClientOptions: e.common.ClientOptions,
	}

	for _, ext := range extractors {
		if err := ext.Fn(ctx, r, out); err != nil {
			slog.Warn("gcp extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
		}
	}
	return nil
}
