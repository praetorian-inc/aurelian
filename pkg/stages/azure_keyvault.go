package stages

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureKeyVaultDetail represents details about a publicly accessible key vault
type AzureKeyVaultDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	NetworkAclsEnabled  bool   `json:"networkAclsEnabled"`
	DefaultAction       string `json:"defaultAction"`
}

// AzureKeyVaultStage checks for publicly accessible key vaults using Azure Resource Graph
func AzureKeyVaultStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.Result {
	logger := logs.NewStageLogger(ctx, opts, "AzureKeyVaultStage")
	out := make(chan types.Result)

	go func() {
		defer close(out)

		// Initialize ARG client
		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible key vaults", subscription)

			// Query for publicly accessible key vaults
			vaultQuery := `
                resources
                | where type =~ 'Microsoft.KeyVault/vaults'
                | extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
                | extend networkAcls = properties.networkAcls
                | extend networkAclsEnabled = isnotnull(networkAcls)
                | extend defaultAction = tolower(coalesce(networkAcls.defaultAction, 'allow'))
                | where publicNetworkAccess != 'disabled'
                | where defaultAction =~ 'allow'
                | project
                    id,
                    name,
                    type,
                    location,
                    publicNetworkAccess,
                    networkAclsEnabled,
                    defaultAction
                | order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*AzureKeyVaultDetail)

			err = argClient.ExecutePaginatedQuery(ctx, vaultQuery, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing key vaults",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					if _, exists := details[helpers.SafeGetString(item, "id")]; !exists {
						detail := &AzureKeyVaultDetail{
							ID:                  helpers.SafeGetString(item, "id"),
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							NetworkAclsEnabled:  helpers.SafeGetBool(item, "networkAclsEnabled"),
							DefaultAction:       helpers.SafeGetString(item, "defaultAction"),
						}

						details[detail.ID] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query key vaults",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*AzureKeyVaultDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible key vaults in subscription %s", len(detailsList), subscription)
				select {
				case out <- types.NewResult(modules.Azure, "public-access", detailsList):
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible key vaults found in subscription %s", subscription)
			}
		}
	}()

	return out
}
