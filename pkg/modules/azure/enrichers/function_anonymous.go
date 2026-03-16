package enrichers

import (
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("microsoft.web/sites", enrichFunctionAnonymousAccess)
}

func enrichFunctionAnonymousAccess(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) error {
	kind, _ := result.Properties["kind"].(string)
	if !strings.Contains(strings.ToLower(kind), "functionapp") {
		return nil
	}

	subID, rg, name, err := enrichment.ParseResource(*result)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, nil)
	if err != nil {
		return err
	}

	pager := client.NewListFunctionsPager(rg, name, nil)
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			slog.Warn("could not list functions, skipping",
				"resource", result.ResourceID, "error", err)
			return nil
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
					result.Properties["hasAnonymousHttpTrigger"] = true
					return nil
				}
			}
		}
	}

	result.Properties["hasAnonymousHttpTrigger"] = false
	return nil
}
