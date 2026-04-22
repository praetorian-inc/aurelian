package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armapimanagement "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"

	"github.com/praetorian-inc/aurelian/pkg/azure/apim"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	plugin.Register(&AzureAPIMMissingAuthModule{})
}

type AzureAPIMMissingAuthConfig struct {
	plugin.AzureCommonRecon
}

type AzureAPIMMissingAuthModule struct {
	AzureAPIMMissingAuthConfig
}

func (m *AzureAPIMMissingAuthModule) ID() string                { return "apim-missing-auth" }
func (m *AzureAPIMMissingAuthModule) Name() string              { return "Azure APIM Missing Authentication" }
func (m *AzureAPIMMissingAuthModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureAPIMMissingAuthModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureAPIMMissingAuthModule) OpsecLevel() string        { return "moderate" }
func (m *AzureAPIMMissingAuthModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureAPIMMissingAuthModule) Description() string {
	return "Detects Azure API Management APIs (including MCP servers exposed via APIM) that have no authentication " +
		"controls at the service, product, or API scope. Inspects policy XML for validate-jwt, validate-azure-ad-token, " +
		"ip-filter, and auth-header check-header elements, and confirms whether a subscription is required."
}

func (m *AzureAPIMMissingAuthModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/api-management/api-management-access-restriction-policies",
		"https://learn.microsoft.com/en-us/azure/api-management/authentication-authorization-overview",
		"https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions",
	}
}

func (m *AzureAPIMMissingAuthModule) SupportedResourceTypes() []string {
	return []string{"Microsoft.ApiManagement/service"}
}

func (m *AzureAPIMMissingAuthModule) Parameters() any {
	return &m.AzureAPIMMissingAuthConfig
}

// apimServiceTarget is the unit of work fanned out per APIM service discovered via ARG.
type apimServiceTarget struct {
	SubscriptionID string
	ResourceGroup  string
	ServiceName    string
	ResourceID     string
}

func (m *AzureAPIMMissingAuthModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
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

	cfg.Info("scanning %d Azure subscriptions for APIM services", len(subIDs))

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

	pipeline.Pipe(targets, m.classifyService(ctx), out, &pipeline.PipeOpts{
		Concurrency: m.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("APIM missing-auth scan complete")
	return nil
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

func (m *AzureAPIMMissingAuthModule) classifyService(ctx context.Context) func(apimServiceTarget, *pipeline.P[model.AurelianModel]) error {
	return func(t apimServiceTarget, out *pipeline.P[model.AurelianModel]) error {
		factory, err := armapimanagement.NewClientFactory(t.SubscriptionID, m.AzureCredential, nil)
		if err != nil {
			return fmt.Errorf("failed to create APIM client factory for %s: %w", t.ResourceID, err)
		}

		servicePolicy := fetchServicePolicyAuth(ctx, factory, t)

		apis, err := listAPIs(ctx, factory, t)
		if err != nil {
			slog.Warn("skipping APIM service — could not list APIs",
				"service", t.ResourceID, "error", err)
			return nil
		}

		for _, api := range apis {
			api.APIPolicyAuth = fetchAPIPolicyAuth(ctx, factory, t, api.APIID)
			api.ProductPolicyAuths = fetchProductPolicyAuths(ctx, factory, t, api.APIID)
			api.Operations = listAPIOperations(ctx, factory, t, api.APIID)
			api.IsMCPServer = apim.IsMCPServer(api.Operations)

			verdict := apim.ClassifyAPI(api, servicePolicy)
			if verdict.IsAuthenticated {
				continue
			}

			emitMissingAuthRisk(out, t, api, verdict, servicePolicy)
		}
		return nil
	}
}

// fetchServicePolicyAuth returns the auth posture derived from the APIM
// service's global inbound policy. Missing / forbidden policies yield an
// empty posture (treated as "no auth").
func fetchServicePolicyAuth(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget) apim.AuthPosture {
	resp, err := factory.NewPolicyClient().Get(ctx, t.ResourceGroup, t.ServiceName, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		if !isNotFound(err) {
			slog.Warn("could not fetch APIM service policy", "service", t.ResourceID, "error", err)
		}
		return apim.AuthPosture{}
	}
	return apim.ParseInboundAuth(policyValue(resp.Properties), nil)
}

func listAPIs(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget) ([]apim.APIInventoryItem, error) {
	pager := factory.NewAPIClient().NewListByServicePager(t.ResourceGroup, t.ServiceName, nil)
	paginator := ratelimit.NewAzurePaginator()
	var apis []apim.APIInventoryItem
	err := paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return true, err
		}
		for _, api := range page.Value {
			apis = append(apis, toInventoryItem(api))
		}
		return pager.More(), nil
	})
	return apis, err
}

func toInventoryItem(api *armapimanagement.APIContract) apim.APIInventoryItem {
	item := apim.APIInventoryItem{}
	if api == nil {
		return item
	}
	if api.Name != nil {
		item.APIID = *api.Name
	}
	if api.Properties == nil {
		return item
	}
	if api.Properties.DisplayName != nil {
		item.DisplayName = *api.Properties.DisplayName
	}
	if api.Properties.Path != nil {
		item.Path = *api.Properties.Path
	}
	if api.Properties.SubscriptionRequired != nil {
		item.SubscriptionRequired = *api.Properties.SubscriptionRequired
	}
	for _, p := range api.Properties.Protocols {
		if p != nil {
			item.Protocols = append(item.Protocols, string(*p))
		}
	}
	return item
}

// listAPIOperations returns every operation defined on an API. URL templates
// are the signal we need for MCP classification; we don't need operation-scope
// policies for API-level auth classification (operation auth only gates a
// single operation, not the API as a whole).
func listAPIOperations(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget, apiID string) []apim.OperationInventoryItem {
	pager := factory.NewAPIOperationClient().NewListByAPIPager(t.ResourceGroup, t.ServiceName, apiID, nil)
	paginator := ratelimit.NewAzurePaginator()
	var ops []apim.OperationInventoryItem
	err := paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return true, err
		}
		for _, op := range page.Value {
			if op == nil || op.Properties == nil {
				continue
			}
			item := apim.OperationInventoryItem{}
			if op.Name != nil {
				item.OperationID = *op.Name
			}
			if op.Properties.DisplayName != nil {
				item.DisplayName = *op.Properties.DisplayName
			}
			if op.Properties.Method != nil {
				item.Method = *op.Properties.Method
			}
			if op.Properties.URLTemplate != nil {
				item.URLTemplate = *op.Properties.URLTemplate
			}
			ops = append(ops, item)
		}
		return pager.More(), nil
	})
	if err != nil && !isNotFound(err) {
		slog.Warn("could not list API operations", "service", t.ResourceID, "api", apiID, "error", err)
	}
	return ops
}

func fetchAPIPolicyAuth(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget, apiID string) apim.AuthPosture {
	resp, err := factory.NewAPIPolicyClient().Get(ctx, t.ResourceGroup, t.ServiceName, apiID, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		if !isNotFound(err) {
			slog.Warn("could not fetch API policy", "service", t.ResourceID, "api", apiID, "error", err)
		}
		return apim.AuthPosture{}
	}
	return apim.ParseInboundAuth(policyValue(resp.Properties), nil)
}

func fetchProductPolicyAuths(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget, apiID string) []apim.AuthPosture {
	productIDs, err := listAPIProducts(ctx, factory, t, apiID)
	if err != nil {
		slog.Warn("could not list products for API", "service", t.ResourceID, "api", apiID, "error", err)
		return nil
	}
	postures := make([]apim.AuthPosture, 0, len(productIDs))
	productClient := factory.NewProductPolicyClient()
	for _, productID := range productIDs {
		resp, err := productClient.Get(ctx, t.ResourceGroup, t.ServiceName, productID, armapimanagement.PolicyIDNamePolicy, nil)
		if err != nil {
			if !isNotFound(err) {
				slog.Warn("could not fetch product policy",
					"service", t.ResourceID, "product", productID, "error", err)
			}
			postures = append(postures, apim.AuthPosture{})
			continue
		}
		postures = append(postures, apim.ParseInboundAuth(policyValue(resp.Properties), nil))
	}
	return postures
}

func listAPIProducts(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget, apiID string) ([]string, error) {
	pager := factory.NewAPIProductClient().NewListByApisPager(t.ResourceGroup, t.ServiceName, apiID, nil)
	paginator := ratelimit.NewAzurePaginator()
	var ids []string
	err := paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return true, err
		}
		for _, p := range page.Value {
			if p != nil && p.Name != nil {
				ids = append(ids, *p.Name)
			}
		}
		return pager.More(), nil
	})
	return ids, err
}

func policyValue(props *armapimanagement.PolicyContractProperties) string {
	if props == nil || props.Value == nil {
		return ""
	}
	return *props.Value
}

// isNotFound reports whether err is an Azure ResponseError with a 404 / 403 /
// 401 status code. APIM returns 404 when a policy has never been set at a
// scope (which is exactly what "no auth" looks like), and 403/401 for
// insufficient permissions.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusNotFound, http.StatusForbidden, http.StatusUnauthorized:
			return true
		}
	}
	return false
}

type missingAuthContext struct {
	APIMServiceID        string             `json:"apim_service_id"`
	APIMServiceName      string             `json:"apim_service_name"`
	APIID                string             `json:"api_id"`
	APIDisplayName       string             `json:"api_display_name,omitempty"`
	APIPath              string             `json:"api_path,omitempty"`
	Protocols            []string           `json:"protocols,omitempty"`
	IsMCPServer          bool               `json:"is_mcp_server"`
	SubscriptionRequired bool               `json:"subscription_required"`
	ServicePolicyAuth    apim.AuthPosture   `json:"service_policy_auth"`
	APIPolicyAuth        apim.AuthPosture   `json:"api_policy_auth"`
	ProductPolicyAuths   []apim.AuthPosture `json:"product_policy_auths,omitempty"`
}

func emitMissingAuthRisk(out *pipeline.P[model.AurelianModel], t apimServiceTarget, api apim.APIInventoryItem, _ apim.APIVerdict, servicePolicy apim.AuthPosture) {
	ctxPayload := missingAuthContext{
		APIMServiceID:        t.ResourceID,
		APIMServiceName:      t.ServiceName,
		APIID:                api.APIID,
		APIDisplayName:       api.DisplayName,
		APIPath:              api.Path,
		Protocols:            api.Protocols,
		IsMCPServer:          api.IsMCPServer,
		SubscriptionRequired: api.SubscriptionRequired,
		ServicePolicyAuth:    servicePolicy,
		APIPolicyAuth:        api.APIPolicyAuth,
		ProductPolicyAuths:   api.ProductPolicyAuths,
	}
	rawCtx, err := json.Marshal(ctxPayload)
	if err != nil {
		slog.Warn("failed to marshal APIM missing-auth context", "error", err)
		return
	}

	name := "azure-apim-missing-auth"
	if api.IsMCPServer {
		name = "azure-apim-mcp-missing-auth"
	}

	out.Send(output.AurelianRisk{
		Name:               name,
		Severity:           output.RiskSeverityCritical,
		ImpactedResourceID: t.ResourceID,
		DeduplicationID:    strings.Join([]string{t.ResourceID, api.APIID}, "/"),
		Context:            rawCtx,
	})
}
