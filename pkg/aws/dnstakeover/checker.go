package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DNSTakeoverChecker dispatches Route53 records to registered checkers by record type.
// Mirrors AWSExtractor from pkg/aws/extraction/extractor.go.
type DNSTakeoverChecker struct {
	ctx CheckContext
}

// NewDNSTakeoverChecker creates a checker with shared AWS options.
func NewDNSTakeoverChecker(ctx context.Context, opts plugin.AWSCommonRecon) (*DNSTakeoverChecker, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create aws config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve account id: %w", err)
	}

	return &DNSTakeoverChecker{
		ctx: CheckContext{
			Ctx:       ctx,
			Opts:      opts,
			AccountID: accountID,
			EIPCache:  &eipCache{},
		},
	}, nil
}

// Check is the pipeline-compatible method that dispatches to registered checkers.
func (c *DNSTakeoverChecker) Check(rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	checkers := getCheckers(rec.Type)
	if len(checkers) == 0 {
		return nil // no checkers registered for this record type — skip silently
	}

	for _, chk := range checkers {
		if err := chk.Fn(c.ctx, rec, out); err != nil {
			slog.Warn("takeover checker failed",
				"name", chk.Name,
				"record_type", rec.Type,
				"record", rec.RecordName,
				"error", err,
			)
		}
	}
	return nil
}
