// pkg/stages/azure_cosmosdb.go
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

// CosmosDBDetail represents details about a publicly accessible Cosmos DB account
type CosmosDBDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	DefaultAction       string `json:"defaultAction"`
	EnableFreeTier      bool   `json:"enableFreeTier"`
	Kind                string `json:"kind"`
	Endpoint            string `json:"endpoint"`
}

// AzureCosmosDBStage checks for publicly accessible Cosmos DB accounts using Azure Resource Graph
func AzureCosmosDBStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*CosmosDBDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureCosmosDBStage")
	out := make(chan []*CosmosDBDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible Cosmos DB accounts", subscription)

			// Query for publicly accessible Cosmos DB accounts
			query := `
                resources
				| where type =~ 'Microsoft.DocumentDB/databaseAccounts'
				| extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
				| extend networkSettings = properties.networkAclBypass
				| extend ipRules = array_length(properties.ipRules)
				| extend defaultAction = tolower(coalesce(properties.networkAcls.defaultAction, 'allow'))
				| extend enableFreeTier = properties.enableFreeTier
				| extend endpoint = properties.documentEndpoint
				| where publicNetworkAccess != 'disabled'
				| where defaultAction == 'allow' or
					ipRules == 0 or
					properties.ipRules has '0.0.0.0' or
					properties.ipRules has '0.0.0.0/0' or
					properties.ipRules has '*' or
					properties.ipRules has 'Internet'
				| project
					id,
					name,
					type,
					location,
					publicNetworkAccess,
					defaultAction,
					enableFreeTier,
					kind,
					endpoint
				| order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*CosmosDBDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing Cosmos DB accounts",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					id := helpers.SafeGetString(item, "id")
					if _, exists := details[id]; !exists {
						detail := &CosmosDBDetail{
							ID:                  id,
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							DefaultAction:       helpers.SafeGetString(item, "defaultAction"),
							EnableFreeTier:      helpers.SafeGetBool(item, "enableFreeTier"),
							Kind:                helpers.SafeGetString(item, "kind"),
							Endpoint:            helpers.SafeGetString(item, "endpoint"),
						}

						details[id] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query Cosmos DB accounts",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*CosmosDBDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible Cosmos DB accounts in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible Cosmos DB accounts found in subscription %s", subscription)
			}
		}
	}()

	return out
}
