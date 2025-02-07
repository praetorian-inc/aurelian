// pkg/stages/azure_acr.go
package stages

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// ContainerRegistryDetail represents details about a publicly accessible ACR
type ContainerRegistryDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	AdminEnabled        bool   `json:"adminEnabled"`
	Sku                 string `json:"sku"`
	LoginServer         string `json:"loginServer"`
}

// AzureContainerRegistryStage checks for publicly accessible ACR instances using Azure Resource Graph
func AzureContainerRegistryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*ContainerRegistryDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureContainerRegistryStage")
	out := make(chan []*ContainerRegistryDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible container registries", subscription)

			// Query for publicly accessible ACRs
			query := `
				resources
				| where type =~ 'Microsoft.ContainerRegistry/registries'
				| extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
				| extend networkRuleSet = properties.networkRuleSet
				| extend adminUserEnabled = properties.adminUserEnabled
				| extend sku = properties.sku.name
				| extend loginServer = properties.loginServer
				| where publicNetworkAccess != 'disabled'
				| extend defaultAction = tolower(coalesce(networkRuleSet.defaultAction, 'allow'))
				| extend ipRules = networkRuleSet.ipRules
				| where 
					defaultAction == 'allow' or
					isnull(ipRules) or
					ipRules has '0.0.0.0/0' or 
					ipRules has '*' or 
					ipRules has 'Internet'
				| project
					id,
					name,
					type,
					location,
					publicNetworkAccess,
					adminUserEnabled,
					sku,
					loginServer
				| order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*ContainerRegistryDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing container registries",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					id := helpers.SafeGetString(item, "id")
					if _, exists := details[id]; !exists {
						detail := &ContainerRegistryDetail{
							ID:                  id,
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							AdminEnabled:        helpers.SafeGetBool(item, "adminUserEnabled"),
							Sku:                 helpers.SafeGetString(item, "sku"),
							LoginServer:         helpers.SafeGetString(item, "loginServer"),
						}

						details[id] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query container registries",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*ContainerRegistryDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible container registries in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible container registries found in subscription %s", subscription)
			}
		}
	}()

	return out
}
