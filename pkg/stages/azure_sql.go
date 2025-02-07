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

// SqlServerDetail represents details about a publicly accessible SQL server
type SqlServerDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	MinimalTlsVersion   string `json:"minimalTlsVersion"`
	Scope               string `json:"scope"`
}

// AzureSqlStage checks for publicly accessible SQL servers using Azure Resource Graph
func AzureSqlStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*SqlServerDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureSqlStage")
	out := make(chan []*SqlServerDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible SQL servers", subscription)

			// Query for publicly accessible SQL servers
			query := `
                resources
                | where type =~ 'Microsoft.Sql/servers'
                | extend publicNetworkAccess = iif(isnotempty(properties.publicNetworkAccess), tolower(properties.publicNetworkAccess), 'enabled')
                | extend minimalTlsVersion = tostring(properties.minimalTlsVersion)
                | mv-expand firewallRule = properties.firewallRules
                | extend startIp = tostring(firewallRule.startIpAddress)
                | extend endIp = tostring(firewallRule.endIpAddress)
                | extend hasPublicAccess = startIp == '0.0.0.0' and endIp == '255.255.255.255'
                | where publicNetworkAccess != 'disabled'
                | where hasPublicAccess
                | project
                    id,
                    name,
                    type,
                    location,
                    publicNetworkAccess,
                    minimalTlsVersion,
                    scope = 'server'
                | distinct
                    id,
                    name,
                    type,
                    location,
                    publicNetworkAccess,
                    minimalTlsVersion,
                    scope
                | order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*SqlServerDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing SQL servers",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					if _, exists := details[helpers.SafeGetString(item, "id")]; !exists {
						detail := &SqlServerDetail{
							ID:                  helpers.SafeGetString(item, "id"),
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							MinimalTlsVersion:   helpers.SafeGetString(item, "minimalTlsVersion"),
							Scope:               helpers.SafeGetString(item, "scope"),
						}

						details[detail.ID] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query SQL servers",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*SqlServerDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible SQL servers in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible SQL servers found in subscription %s", subscription)
			}
		}
	}()

	return out
}
