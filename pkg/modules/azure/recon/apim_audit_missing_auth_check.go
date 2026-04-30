package recon

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	armapimanagement "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"

	"github.com/praetorian-inc/aurelian/pkg/azure/apim"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// checkMissingAuth audits APIs (including MCP servers) on the target service for
// missing authentication controls at the service, product, or API scope. Emits
// azure-apim-missing-auth (or azure-apim-mcp-missing-auth for MCP servers) per
// unauthenticated API.
func (m *AzureAPIMAuditModule) checkMissingAuth(c *apimCheckContext, out *pipeline.P[model.AurelianModel]) {
	t := c.target
	servicePolicy := fetchServicePolicyAuth(c.ctx, c.factory, t)

	apis, err := apim.ListAPIs(c.ctx, m.AzureCredential, t.SubscriptionID, t.ResourceGroup, t.ServiceName)
	if err != nil {
		slog.Warn("skipping APIM service — could not list APIs",
			"service", t.ResourceID, "error", err)
		return
	}

	for _, api := range apis {
		api.APIPolicyAuth = fetchAPIPolicyAuth(c.ctx, c.factory, t, api.APIID)
		api.ProductPolicyAuths = fetchProductPolicyAuths(c.ctx, c.factory, t, api.APIID)
		if !api.IsMCPServer {
			// Native MCP-type APIs have no classic operations (their tools are a
			// different sub-resource). Skip the call for MCP; fall back to
			// operation-path heuristic for non-native APIs so proxy-shaped MCPs
			// (e.g., regular APIs with a /mcp operation) are still labeled.
			api.Operations = listAPIOperations(c.ctx, c.factory, t, api.APIID)
			api.IsMCPServer = apim.IsMCPServer(api.Operations)
		}

		verdict := apim.ClassifyAPI(api, servicePolicy)
		if verdict.IsAuthenticated {
			continue
		}

		emitMissingAuthRisk(out, t, api, verdict, servicePolicy)
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
