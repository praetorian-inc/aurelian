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

// AzureStorageAccountDetail represents details about a publicly accessible storage account
type AzureStorageAccountDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	DefaultAction       string `json:"defaultAction"`
}

// AzureStorageAccountStage checks for publicly accessible storage accounts using Azure Resource Graph
func AzureStorageAccountStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*AzureStorageAccountDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureStorageAccountStage")
	out := make(chan []*AzureStorageAccountDetail)

	go func() {
		defer close(out)

		// Initialize ARG client
		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible storage accounts", subscription)

			// Query for publicly accessible storage accounts
			storageQuery := `
                resources
                | where type =~ 'Microsoft.Storage/storageAccounts'
                | extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
                | extend networkAcls = properties.networkAcls
                | extend defaultAction = tolower(coalesce(networkAcls.defaultAction, 'allow'))
                | where publicNetworkAccess != 'disabled'
                | where defaultAction =~ 'allow'
                | project
                    id,
                    name,
                    type,
                    location,
                    publicNetworkAccess,
                    defaultAction
                | order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*AzureStorageAccountDetail)

			err = argClient.ExecutePaginatedQuery(ctx, storageQuery, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing storage accounts",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					if _, exists := details[helpers.SafeGetString(item, "id")]; !exists {
						detail := &AzureStorageAccountDetail{
							ID:                  helpers.SafeGetString(item, "id"),
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							DefaultAction:       helpers.SafeGetString(item, "defaultAction"),
						}

						details[detail.ID] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query storage accounts",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*AzureStorageAccountDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible storage accounts in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible storage accounts found in subscription %s", subscription)
			}
		}
	}()

	return out
}
