// pkg/stages/azure_appservice.go
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

// AppServiceDetail represents details about a publicly accessible app service
type AppServiceDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess bool   `json:"publicNetworkAccess"`
	Kind                string `json:"kind"`
}

// AzureAppServiceStage checks for publicly accessible app services using Azure Resource Graph
func AzureAppServiceStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*AppServiceDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureAppServiceStage")
	out := make(chan []*AppServiceDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible app services", subscription)

			// Query for publicly accessible app services
			query := `
               resources
				| where type =~ 'microsoft.web/sites'
				| extend publicAccess = iif(
					isnull(properties.virtualNetworkSubnetId) or properties.virtualNetworkSubnetId == '', 
					true, 
					false
				)
				| where publicAccess == true
				| project
					id,
					name,
					type,
					location,
					publicNetworkAccess = publicAccess,
					kind
				| order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*AppServiceDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing app services",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					if _, exists := details[helpers.SafeGetString(item, "id")]; !exists {
						detail := &AppServiceDetail{
							ID:                  helpers.SafeGetString(item, "id"),
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: true, // If it's in results, it's public
							Kind:                helpers.SafeGetString(item, "kind"),
						}

						details[detail.ID] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query app services",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*AppServiceDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible app services in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible app services found in subscription %s", subscription)
			}
		}
	}()

	return out
}
