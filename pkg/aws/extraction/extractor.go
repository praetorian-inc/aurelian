package extraction

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// Config configures extractor behavior.
type Config struct {
	MaxEvents   int
	MaxStreams  int
	NewestFirst bool
	// FailOnError makes extraction failures fail the pipeline instead of producing
	// partial results. Incremental callers need this guarantee before advancing a
	// successful-scan checkpoint.
	FailOnError bool
}

// AWSExtractor extracts scanable content from AWS resources.
type AWSExtractor struct {
	opts             plugin.AWSCommonRecon
	cfg              Config
	crossRegionActor *ratelimit.CrossRegionActor
}

// NewAWSExtractor creates an extractor with shared AWS options.
func NewAWSExtractor(opts plugin.AWSCommonRecon, cfg Config) *AWSExtractor {
	return &AWSExtractor{
		opts:             opts,
		cfg:              cfg,
		crossRegionActor: ratelimit.NewCrossRegionActor(opts.Concurrency),
	}
}

// Extract is a pipeline-compatible method that dispatches by resource type.
func (e *AWSExtractor) Extract(r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	return e.crossRegionActor.ActInRegion(r.Region, func() error {
		extractors := getExtractors(r.ResourceType)
		if len(extractors) == 0 {
			return fmt.Errorf("no extractor registered for resource type %s", r.ResourceType)
		}

		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{Region: r.Region, Profile: e.opts.Profile, ProfileDir: e.opts.ProfileDir})
		if err != nil {
			slog.Warn("failed to create AWS config for extraction, skipping extractors", "resource", r.ResourceID, "region", r.Region, "error", err)
			if e.cfg.FailOnError {
				return fmt.Errorf("create AWS config for %s: %w", r.ResourceID, err)
			}
			return nil
		}

		ec := extractContext{Context: context.Background(), AWSConfig: awsCfg, Config: e.cfg, Concurrency: e.opts.Concurrency}
		var errs error
		for _, ext := range extractors {
			if err := ext.Fn(ec, r, out); err != nil {
				slog.Warn("extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
				errs = errors.Join(errs, fmt.Errorf("%s: %w", ext.Name, err))
			}
		}
		if e.cfg.FailOnError && errs != nil {
			return fmt.Errorf("extract %s: %w", r.ResourceID, errs)
		}
		return nil
	})
}
