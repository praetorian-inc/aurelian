package recon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armapimanagement "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureAPIMAuditModule{})
}

type AzureAPIMAuditConfig struct {
	plugin.AzureCommonRecon
}

type AzureAPIMAuditModule struct {
	AzureAPIMAuditConfig
}

func (m *AzureAPIMAuditModule) ID() string                { return "apim-audit" }
func (m *AzureAPIMAuditModule) Name() string              { return "Azure APIM Audit" }
func (m *AzureAPIMAuditModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureAPIMAuditModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureAPIMAuditModule) OpsecLevel() string        { return "moderate" }
func (m *AzureAPIMAuditModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureAPIMAuditModule) Description() string {
	return "Audits Azure API Management services for security weaknesses across two checks: " +
		"(1) APIs (including MCP servers) with no authentication controls at the service, product, or API scope " +
		"— inspects policy XML for validate-jwt, validate-azure-ad-token, ip-filter, and check-header elements, " +
		"and confirms whether a subscription is required; (2) backends configured behind APIM that are reachable " +
		"without traversing the gateway — Azure App Service backends are checked for publicNetworkAccess and IP " +
		"restrictions, non-Azure backends (OpenShift, GCP Cloud Run, internal hosts) are flagged for manual triage."
}

func (m *AzureAPIMAuditModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/api-management/api-management-access-restriction-policies",
		"https://learn.microsoft.com/en-us/azure/api-management/authentication-authorization-overview",
		"https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions",
		"https://learn.microsoft.com/en-us/azure/app-service/environment/networking",
		"https://learn.microsoft.com/en-us/azure/api-management/virtual-network-concepts",
	}
}

func (m *AzureAPIMAuditModule) SupportedResourceTypes() []string {
	return []string{"Microsoft.ApiManagement/service"}
}

func (m *AzureAPIMAuditModule) Parameters() any {
	return &m.AzureAPIMAuditConfig
}

// apimServiceTarget is the unit of work fanned out per APIM service discovered via ARG.
type apimServiceTarget struct {
	SubscriptionID string
	ResourceGroup  string
	ServiceName    string
	ResourceID     string
}

// apimCheckContext bundles everything a per-service check needs: the discovered
// target, a ready-built APIM client factory scoped to its subscription, and a
// shared ARG client for cross-resource lookups.
type apimCheckContext struct {
	ctx       context.Context
	target    apimServiceTarget
	factory   *armapimanagement.ClientFactory
	argClient *armresourcegraph.Client
}

// apimCheck is one audit rule that inspects a single APIM service and emits
// any risks it finds into out.
type apimCheck func(c *apimCheckContext, out *pipeline.P[model.AurelianModel])

func (m *AzureAPIMAuditModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		return err
	}
	if len(subIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	cfg.Info("auditing APIM services across %d Azure subscriptions", len(subIDs))

	argClient, err := armresourcegraph.NewClient(m.AzureCredential, nil)
	if err != nil {
		// Backend check needs ARG; without it we can still run missing-auth.
		slog.Warn("could not create ARG client — backend correlation lookups will be skipped", "error", err)
	}

	idStream := pipeline.From(subIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	lister := resourcegraph.NewResourceGraphLister(m.AzureCredential, nil)
	apimResources := pipeline.New[output.AzureResource]()
	pipeline.Pipe(resolvedSubs, func(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
		return lister.List(resourcegraph.ListerInput{
			Subscription:  sub,
			ResourceTypes: []string{"Microsoft.ApiManagement/service"},
		}, out)
	}, apimResources)

	targets := pipeline.New[apimServiceTarget]()
	pipeline.Pipe(apimResources, toAPIMTarget, targets)

	checks := []apimCheck{m.checkMissingAuth}
	if argClient != nil {
		// Backend direct-access correlation needs ARG to look up App Service
		// reachability; if ARG init failed we skip the check entirely (logged
		// above) rather than emit Low backend-unverified findings for every
		// Azure App Service backend.
		checks = append(checks, m.checkBackendDirectAccess)
	}

	pipeline.Pipe(targets, m.runChecks(ctx, argClient, checks), out, &pipeline.PipeOpts{
		Concurrency: m.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("APIM audit complete")
	return nil
}

func (m *AzureAPIMAuditModule) runChecks(ctx context.Context, argClient *armresourcegraph.Client, checks []apimCheck) func(apimServiceTarget, *pipeline.P[model.AurelianModel]) error {
	return func(t apimServiceTarget, out *pipeline.P[model.AurelianModel]) error {
		factory, err := armapimanagement.NewClientFactory(t.SubscriptionID, m.AzureCredential, nil)
		if err != nil {
			return fmt.Errorf("failed to create APIM client factory for %s: %w", t.ResourceID, err)
		}
		c := &apimCheckContext{
			ctx:       ctx,
			target:    t,
			factory:   factory,
			argClient: argClient,
		}
		for _, check := range checks {
			check(c, out)
		}
		return nil
	}
}

func toAPIMTarget(r output.AzureResource, out *pipeline.P[apimServiceTarget]) error {
	parsed, err := arm.ParseResourceID(r.ResourceID)
	if err != nil {
		slog.Warn("skipping unparseable APIM resource ID", "id", r.ResourceID, "error", err)
		return nil
	}
	out.Send(apimServiceTarget{
		SubscriptionID: parsed.SubscriptionID,
		ResourceGroup:  parsed.ResourceGroupName,
		ServiceName:    parsed.Name,
		ResourceID:     r.ResourceID,
	})
	return nil
}

func policyValue(props *armapimanagement.PolicyContractProperties) string {
	if props == nil || props.Value == nil {
		return ""
	}
	return *props.Value
}

// isPolicyNotConfigured reports whether err corresponds to a 404 from ARM,
// which APIM uses to indicate "no custom policy has been set at this scope".
// That is semantically the same as `<inbound><base /></inbound>` — the parent
// scope's policies run unmodified.
//
// Permission errors (401/403) are intentionally NOT treated as "not configured"
// here — silently downgrading them to "no auth" produces false-positive
// missing-auth findings when the auditor lacks read on a policy scope. Use
// isPermissionDenied to handle those separately.
func isPolicyNotConfigured(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusNotFound
	}
	return false
}

