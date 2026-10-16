package dnstakeover

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DNSTakeoverChecker dispatches Azure DNS records to registered checkers by record type.
type DNSTakeoverChecker struct {
	ctx CheckContext
}

// NewDNSTakeoverChecker creates a checker with shared Azure credentials and options.
// subscriptionIDs should contain the resolved (not "all") subscription IDs for cross-subscription lookups.
func NewDNSTakeoverChecker(ctx context.Context, opts plugin.AzureCommonRecon, subscriptionIDs []string) *DNSTakeoverChecker {
	if azurecloud.ForCredential(opts.AzureCredential).Name == azurecloud.Government {
		slog.Warn("Azure Government DNS scan has unsupported checks; results are partial, not a clean bill of health", "checks", "CDN Classic, Front Door Classic, NS delegation (Government suffix/availability unverified)")
	}
	return &DNSTakeoverChecker{
		ctx: CheckContext{
			Ctx:             ctx,
			Opts:            opts,
			Credential:      opts.AzureCredential,
			SubscriptionIDs: subscriptionIDs,
			PublicIPCache:   &publicIPCache{},
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
		if azurecloud.ForCredential(checkCtx.Credential).Name == azurecloud.Government && (chk.Name == "cdn-takeover" || chk.Name == "frontdoor-takeover" || chk.Name == "ns-delegation") {
			continue
		}
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
