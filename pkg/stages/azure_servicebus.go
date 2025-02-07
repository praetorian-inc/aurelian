// pkg/stages/azure_servicebus.go
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

// ServiceBusDetail represents details about a publicly accessible Service Bus namespace
type ServiceBusDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	DefaultAction       string `json:"defaultAction"`
	Sku                 string `json:"sku"`
	Endpoint            string `json:"endpoint"`
	ZoneRedundant       bool   `json:"zoneRedundant"`
}

// AzureServiceBusStage checks for publicly accessible Service Bus namespaces using Azure Resource Graph
func AzureServiceBusStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*ServiceBusDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureServiceBusStage")
	out := make(chan []*ServiceBusDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible Service Bus namespaces", subscription)

			// Query for publicly accessible Service Bus namespaces
			query := `
                resources
				| where type =~ 'Microsoft.ServiceBus/namespaces'
				| extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
				| extend networkRuleSets = properties.networkRuleSets
				| extend defaultAction = tolower(coalesce(properties.networkRuleSets.defaultAction, 'allow'))
				| extend sku = properties.sku.name
				| extend endpoint = properties.serviceBusEndpoint
				| extend zoneRedundant = properties.zoneRedundant
				| where publicNetworkAccess != 'disabled'
				| where defaultAction == 'allow' or
					isnull(networkRuleSets.ipRules) or
					networkRuleSets.ipRules has '0.0.0.0' or
					networkRuleSets.ipRules has '0.0.0.0/0' or
					networkRuleSets.ipRules has '*' or
					networkRuleSets.ipRules has 'Internet'
				| project
					id,
					name,
					type,
					location,
					publicNetworkAccess,
					defaultAction,
					sku,
					endpoint,
					zoneRedundant
				| order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*ServiceBusDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing Service Bus namespaces",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					id := helpers.SafeGetString(item, "id")
					if _, exists := details[id]; !exists {
						detail := &ServiceBusDetail{
							ID:                  id,
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							DefaultAction:       helpers.SafeGetString(item, "defaultAction"),
							Sku:                 helpers.SafeGetString(item, "sku"),
							Endpoint:            helpers.SafeGetString(item, "endpoint"),
							ZoneRedundant:       helpers.SafeGetBool(item, "zoneRedundant"),
						}

						details[id] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query Service Bus namespaces",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*ServiceBusDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible Service Bus namespaces in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible Service Bus namespaces found in subscription %s", subscription)
			}
		}
	}()

	return out
}
