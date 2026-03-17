package recon

import (
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/dnstakeover"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureSubdomainTakeoverModule{})
}

type AzureSubdomainTakeoverConfig struct {
	plugin.AzureCommonRecon
	Concurrency int `param:"concurrency" desc:"Number of concurrent checker goroutines" default:"5"`
}

type AzureSubdomainTakeoverModule struct {
	AzureSubdomainTakeoverConfig
}

func (m *AzureSubdomainTakeoverModule) ID() string                { return "subdomain-takeover" }
func (m *AzureSubdomainTakeoverModule) Name() string              { return "Azure Subdomain Takeover" }
func (m *AzureSubdomainTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureSubdomainTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureSubdomainTakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *AzureSubdomainTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *AzureSubdomainTakeoverModule) Parameters() any           { return &m.AzureSubdomainTakeoverConfig }

func (m *AzureSubdomainTakeoverModule) Description() string {
	return "Scan for dangling DNS records in Azure DNS zones that could enable subdomain takeover. " +
		"Checks CNAME records for unclaimed App Service, Blob Storage, CDN, and Traffic Manager names; " +
		"A/AAAA records for orphaned public IPs; and NS delegations to non-existent Azure DNS zones."
}

func (m *AzureSubdomainTakeoverModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
		"https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers",
	}
}

func (m *AzureSubdomainTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzureSubdomainTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)

	subscriptionIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		return err
	}

	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	cfg.Info("scanning Azure DNS across %d subscriptions", len(subscriptionIDs))

	checker := dnstakeover.NewDNSTakeoverChecker(cfg.Context, m.AzureCommonRecon, subscriptionIDs)
	enumerator := dnstakeover.NewDNSEnumerator(m.AzureCredential)

	subStream := pipeline.From(subscriptionIDs...)

	records := pipeline.New[dnstakeover.AzureDNSRecord]()
	pipeline.Pipe(subStream, enumerator.EnumerateSubscription, records, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("enumerating azure dns records"),
	})

	pipeline.Pipe(records, checker.Check, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking for takeover"),
		Concurrency: m.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("Azure subdomain takeover scan complete")
	return nil
}
