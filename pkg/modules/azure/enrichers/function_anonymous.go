package enrichers

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("function_app_http_anonymous_access", checkFunctionAnonymousAccess)
}

func checkFunctionAnonymousAccess(cfg plugin.AzureEnricherConfig, result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := enrichment.ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating web apps client: %w", err)
	}

	pager := client.NewListFunctionsPager(rg, name, nil)
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
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
