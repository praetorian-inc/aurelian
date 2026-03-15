package configscan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// TemplatesNeedingEnrichment lists template IDs that require SDK-based
// confirmation. All other templates have ARG-level filtering and pass through.
var TemplatesNeedingEnrichment = map[string]bool{
	"app_service_auth_disabled":            true,
	"app_service_remote_debugging_enabled": true,
	"databases_allow_azure_services":       true,
	"function_app_http_anonymous_access":   true,
	"vm_privileged_managed_identity":       true,
}

// Enricher confirms candidate ARG results via Azure SDK API calls.
// Templates with ARG-level filtering pass through unchanged; enricher-dependent
// templates are confirmed or dropped.
type Enricher struct {
	cred    azcore.TokenCredential
	ctx     context.Context
	clients sync.Map // subscription ID → *armappservice.WebAppsClient
}

func NewEnricher(ctx context.Context, cred azcore.TokenCredential) *Enricher {
	return &Enricher{cred: cred, ctx: ctx}
}

// Enrich is a pipeline-compatible method.
func (e *Enricher) Enrich(result templates.ARGQueryResult, out *pipeline.P[templates.ARGQueryResult]) error {
	if !TemplatesNeedingEnrichment[result.TemplateID] {
		out.Send(result)
		return nil
	}

	confirmed, err := e.confirm(result)
	if err != nil {
		slog.Warn("enrichment failed, dropping candidate",
			"template", result.TemplateID, "resource", result.ResourceID, "error", err)
		return nil
	}
	if confirmed {
		out.Send(result)
	}
	return nil
}

func (e *Enricher) confirm(result templates.ARGQueryResult) (bool, error) {
	switch result.TemplateID {
	case "app_service_auth_disabled":
		return e.checkAppServiceAuth(result)
	case "app_service_remote_debugging_enabled":
		return e.checkRemoteDebugging(result)
	case "databases_allow_azure_services":
		return e.checkDatabaseFirewall(result)
	case "function_app_http_anonymous_access":
		return e.checkFunctionAnonymousAccess(result)
	case "vm_privileged_managed_identity":
		return e.checkVMPrivilegedIdentity(result)
	default:
		return true, nil
	}
}

// ParseResource extracts subscription ID, resource group, and resource name
// from an ARG query result.
func ParseResource(result templates.ARGQueryResult) (subID, rg, name string, err error) {
	subID = result.SubscriptionID
	name = result.ResourceName

	parts := strings.Split(result.ResourceID, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			rg = parts[i+1]
			break
		}
	}
	if subID == "" || rg == "" || name == "" {
		return "", "", "", fmt.Errorf("cannot parse resource ID %q: sub=%q rg=%q name=%q",
			result.ResourceID, subID, rg, name)
	}
	return subID, rg, name, nil
}

func (e *Enricher) webAppsClient(subID string) (*armappservice.WebAppsClient, error) {
	if cached, ok := e.clients.Load(subID); ok {
		return cached.(*armappservice.WebAppsClient), nil
	}
	client, err := armappservice.NewWebAppsClient(subID, e.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating web apps client: %w", err)
	}
	e.clients.Store(subID, client)
	return client, nil
}

func (e *Enricher) checkAppServiceAuth(result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := e.webAppsClient(subID)
	if err != nil {
		return false, err
	}

	authSettings, err := client.GetAuthSettingsV2(e.ctx, rg, name, nil)
	if err != nil {
		return false, fmt.Errorf("getting auth settings for %s: %w", name, err)
	}

	if authSettings.Properties != nil &&
		authSettings.Properties.Platform != nil &&
		authSettings.Properties.Platform.Enabled != nil &&
		*authSettings.Properties.Platform.Enabled {
		return false, nil
	}

	return true, nil
}

func (e *Enricher) checkRemoteDebugging(result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := e.webAppsClient(subID)
	if err != nil {
		return false, err
	}

	config, err := client.GetConfiguration(e.ctx, rg, name, nil)
	if err != nil {
		return false, fmt.Errorf("getting configuration for %s: %w", name, err)
	}

	if config.Properties != nil &&
		config.Properties.RemoteDebuggingEnabled != nil &&
		*config.Properties.RemoteDebuggingEnabled {
		return true, nil
	}

	return false, nil
}

func (e *Enricher) checkFunctionAnonymousAccess(result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := e.webAppsClient(subID)
	if err != nil {
		return false, err
	}

	pager := client.NewListFunctionsPager(rg, name, nil)
	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return false, fmt.Errorf("listing functions for %s: %w", name, err)
		}

		for _, fn := range page.Value {
			if fn.Properties == nil || fn.Properties.Config == nil {
				continue
			}
			configMap, ok := fn.Properties.Config.(map[string]any)
			if !ok {
				continue
			}
			bindings, ok := configMap["bindings"].([]any)
			if !ok {
				continue
			}
			for _, b := range bindings {
				bm, ok := b.(map[string]any)
				if !ok {
					continue
				}
				if bType, _ := bm["type"].(string); bType != "httpTrigger" {
					continue
				}
				if authLevel, _ := bm["authLevel"].(string); strings.EqualFold(authLevel, "anonymous") {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
