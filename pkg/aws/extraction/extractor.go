package extraction

import (
	"context"
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Config configures extractor behavior.
type Config struct {
	MaxEvents   int
	MaxStreams  int
	NewestFirst bool
}

// AWSExtractor extracts scanable content from AWS resources.
type AWSExtractor struct {
	opts plugin.AWSCommonRecon
	cfg  Config
}

// NewAWSExtractor creates an extractor with shared AWS options.
func NewAWSExtractor(opts plugin.AWSCommonRecon, cfg Config) *AWSExtractor {
	return &AWSExtractor{opts: opts, cfg: cfg}
}

// Extract is a pipeline-compatible method that dispatches by resource type.
func (e *AWSExtractor) Extract(r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	extractors := getExtractors(r.ResourceType)
	if len(extractors) == 0 {
		return fmt.Errorf("no extractor registered for resource type %s", r.ResourceType)
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{Region: r.Region, Profile: e.opts.Profile, ProfileDir: e.opts.ProfileDir})
	if err != nil {
		slog.Warn("failed to create AWS config for extraction, skipping extractors", "resource", r.ResourceID, "region", r.Region, "error", err)
		return nil
	}

	ec := extractContext{Context: context.Background(), AWSConfig: awsCfg, Config: e.cfg}
	for _, ext := range extractors {
		if err := ext.Fn(ec, r, out); err != nil {
			slog.Warn("extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
		}
	}
	return nil
}
