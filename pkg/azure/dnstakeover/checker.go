package dnstakeover

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DNSTakeoverChecker dispatches Azure DNS records to registered checkers by record type.
type DNSTakeoverChecker struct {
	ctx CheckContext
}

// NewDNSTakeoverChecker creates a checker with shared Azure credentials and options.
func NewDNSTakeoverChecker(ctx context.Context, opts plugin.AzureCommonRecon) *DNSTakeoverChecker {
	return &DNSTakeoverChecker{
		ctx: CheckContext{
			Ctx:           ctx,
			Opts:          opts,
			Credential:    opts.AzureCredential,
			PublicIPCache: &publicIPCache{},
		},
	}
}

// Check is the pipeline-compatible method that dispatches to registered checkers.
func (c *DNSTakeoverChecker) Check(rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	checkers := getCheckers(rec.Type)
	if len(checkers) == 0 {
		return nil
	}

	checkCtx := c.ctx
	checkCtx.SubscriptionID = rec.SubscriptionID

	for _, chk := range checkers {
		if err := chk.Fn(checkCtx, rec, out); err != nil {
			slog.Warn("takeover checker failed",
				"name", chk.Name,
				"record_type", rec.Type,
				"record", rec.RecordName,
				"zone", rec.ZoneName,
				"error", err,
			)
		}
	}
	return nil
}
