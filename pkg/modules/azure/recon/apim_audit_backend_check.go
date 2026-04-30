package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	armapimanagement "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/praetorian-inc/aurelian/pkg/azure/apim"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// checkBackendDirectAccess audits APIM-configured backends for reachability
// outside the gateway. Azure App Service backends are correlated via ARG and
// flagged azure-apim-backend-direct-access (High) when publicly reachable;
// non-correlated and non-Azure backends are flagged azure-apim-backend-unverified
// (Low) for manual triage.
func (m *AzureAPIMAuditModule) checkBackendDirectAccess(c *apimCheckContext, out *pipeline.P[model.AurelianModel]) {
	t := c.target
	backends, err := listBackends(c.ctx, c.factory, t)
	if err != nil {
		slog.Warn("skipping APIM service — could not list backends",
			"service", t.ResourceID, "error", err)
		return
	}

	for _, b := range backends {
		classifyAndEmitBackend(c.ctx, c.argClient, t, b, out)
	}
}

type apimBackend struct {
	Name     string
	URL      string
	Protocol string
}

func listBackends(ctx context.Context, factory *armapimanagement.ClientFactory, t apimServiceTarget) ([]apimBackend, error) {
	pager := factory.NewBackendClient().NewListByServicePager(t.ResourceGroup, t.ServiceName, nil)
	paginator := ratelimit.NewAzurePaginator()
	var backends []apimBackend
	err := paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return true, err
		}
		for _, be := range page.Value {
			if be == nil {
				continue
			}
			name := ""
			if be.Name != nil {
				name = *be.Name
			}
			url := ""
			if be.Properties != nil && be.Properties.URL != nil {
				url = *be.Properties.URL
			}
			protocol := ""
			if be.Properties != nil && be.Properties.Protocol != nil {
				protocol = string(*be.Properties.Protocol)
			}
			if url == "" {
				continue
			}
			backends = append(backends, apimBackend{Name: name, URL: url, Protocol: protocol})
		}
		return pager.More(), nil
	})
	return backends, err
}

type backendRiskContext struct {
	APIMServiceID        string               `json:"apim_service_id"`
	APIMServiceName      string               `json:"apim_service_name"`
	BackendName          string               `json:"backend_name"`
	BackendURL           string               `json:"backend_url"`
	BackendProtocol      string               `json:"backend_protocol,omitempty"`
	BackendFQDN          string               `json:"backend_fqdn,omitempty"`
	Category             apim.BackendCategory `json:"category"`
	CorrelatedResourceID string               `json:"correlated_resource_id,omitempty"`
	PublicNetworkAccess  string               `json:"public_network_access,omitempty"`
	IPRestrictionRules   int                  `json:"ip_restriction_rules"`
	Reason               string               `json:"reason"`
}

func classifyAndEmitBackend(
	ctx context.Context,
	argClient *armresourcegraph.Client,
	t apimServiceTarget,
	b apimBackend,
	out *pipeline.P[model.AurelianModel],
) {
	cat, fqdn := apim.CategorizeBackendURL(b.URL)
	payload := backendRiskContext{
		APIMServiceID:   t.ResourceID,
		APIMServiceName: t.ServiceName,
		BackendName:     b.Name,
		BackendURL:      b.URL,
		BackendProtocol: b.Protocol,
		BackendFQDN:     fqdn,
		Category:        cat,
	}

	switch cat {
	case apim.BackendAppService, apim.BackendAppServiceEnvironment:
		if argClient == nil {
			// Without ARG we can't correlate the FQDN to an App Service to
			// read publicNetworkAccess / IP restrictions. Emitting Low
			// per-backend in this state would create N findings of pure
			// noise; better to skip silently and let the operator notice
			// the warning logged once at module start.
			return
		}
		exposure := lookupAppServiceExposure(ctx, argClient, fqdn)
		payload.CorrelatedResourceID = exposure.ResourceID
		payload.PublicNetworkAccess = exposure.PublicNetworkAccess
		payload.IPRestrictionRules = exposure.IPRestrictionRules

		if exposure.ResourceID == "" {
			payload.Reason = "backend hostname did not match any App Service in accessible subscriptions — manual verification required"
			emitBackend(out, t, b, payload, output.RiskSeverityLow, "azure-apim-backend-unverified")
			return
		}
		if exposure.IsDirectlyReachable() {
			payload.Reason = "App Service has publicNetworkAccess Enabled and no IP restrictions gating to APIM subnet — reachable outside the gateway"
			emitBackend(out, t, b, payload, output.RiskSeverityHigh, "azure-apim-backend-direct-access")
			return
		}
		// Correlated but not directly reachable — nothing to emit.
		return

	case apim.BackendAPIM:
		// Chained APIM — informational only, not a "direct bypass".
		return

	default:
		payload.Reason = fmt.Sprintf("backend category %q cannot be verified via Azure APIs alone", cat)
		emitBackend(out, t, b, payload, output.RiskSeverityLow, "azure-apim-backend-unverified")
	}
}

type appServiceExposure struct {
	ResourceID          string
	PublicNetworkAccess string
	IPRestrictionRules  int
}

// IsDirectlyReachable reports whether the App Service looks reachable by any
// caller on the network: public access enabled AND no meaningful IP
// restrictions. APIM's default App Service deployments leave a single
// "Deny all" rule in `ipSecurityRestrictions`, so we treat <=1 rule as
// "effectively no gating" for this conservative heuristic.
func (e appServiceExposure) IsDirectlyReachable() bool {
	if !strings.EqualFold(e.PublicNetworkAccess, "Enabled") {
		return false
	}
	return e.IPRestrictionRules <= 1
}

// lookupAppServiceExposure looks up an App Service by its default hostname via
// ARG and returns public-access signals. Empty ResourceID means no match.
func lookupAppServiceExposure(ctx context.Context, client *armresourcegraph.Client, fqdn string) appServiceExposure {
	if client == nil || fqdn == "" {
		return appServiceExposure{}
	}
	// ARG lowercases hostnames in defaultHostName; we search both fields.
	// Escape backslashes BEFORE single quotes — Kusto's `\` escapes the next
	// character, so an FQDN ending in `\` (attacker-controlled backend URL)
	// would otherwise escape the closing quote and break the query.
	//
	// Includes deployment slots (microsoft.web/sites/slots): slot hostnames
	// like `<app>-staging.azurewebsites.net` live on the slot resource, not
	// the parent site, so a query restricted to microsoft.web/sites would
	// miss them and downgrade APIM-backed slot URLs to backend-unverified.
	escaped := strings.ReplaceAll(strings.ToLower(fqdn), `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, "'", "''")
	query := fmt.Sprintf(`resources
| where type =~ 'microsoft.web/sites' or type =~ 'microsoft.web/sites/slots'
| extend defaultHostName = tolower(tostring(properties.defaultHostName))
| extend hostNames = properties.enabledHostNames
| mv-expand hostName = hostNames
| extend hostName = tolower(tostring(hostName))
| where defaultHostName == '%s' or hostName == '%s'
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend ipRestrictionCount = array_length(coalesce(properties.siteConfig.ipSecurityRestrictions, dynamic([])))
| project id, publicNetworkAccess, ipRestrictionCount
| take 1`, escaped, escaped)

	resp, err := client.Resources(ctx, armresourcegraph.QueryRequest{Query: &query}, nil)
	if err != nil {
		slog.Warn("ARG lookup for App Service hostname failed", "fqdn", fqdn, "error", err)
		return appServiceExposure{}
	}
	rows, ok := resp.Data.([]any)
	if !ok || len(rows) == 0 {
		return appServiceExposure{}
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		return appServiceExposure{}
	}
	exposure := appServiceExposure{}
	if v, ok := row["id"].(string); ok {
		exposure.ResourceID = v
	}
	if v, ok := row["publicNetworkAccess"].(string); ok {
		exposure.PublicNetworkAccess = v
	}
	switch v := row["ipRestrictionCount"].(type) {
	case float64:
		exposure.IPRestrictionRules = int(v)
	case int64:
		exposure.IPRestrictionRules = int(v)
	}
	return exposure
}

func emitBackend(out *pipeline.P[model.AurelianModel], t apimServiceTarget, b apimBackend, payload backendRiskContext, sev output.RiskSeverity, name string) {
	raw, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("failed to marshal APIM backend risk context", "error", err)
		return
	}
	out.Send(output.AurelianRisk{
		Name:               name,
		Severity:           sev,
		ImpactedResourceID: t.ResourceID,
		DeduplicationID:    strings.Join([]string{t.ResourceID, "backend", b.Name}, "/"),
		Context:            raw,
	})
}
