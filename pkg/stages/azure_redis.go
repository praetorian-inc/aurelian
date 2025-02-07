// pkg/stages/azure_redis.go
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

// RedisCacheDetail represents details about a publicly accessible Redis Cache
type RedisCacheDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	Sku                 string `json:"sku"`
	EnableNonSslPort    bool   `json:"enableNonSslPort"`
	MinimalTlsVersion   string `json:"minimalTlsVersion"`
	HostName            string `json:"hostName"`
}

// AzureRedisCacheStage checks for publicly accessible Redis Caches using Azure Resource Graph
func AzureRedisCacheStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*RedisCacheDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureRedisCacheStage")
	out := make(chan []*RedisCacheDetail)

	go func() {
		defer close(out)

		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			message.Info("Scanning subscription %s for publicly accessible Redis Caches", subscription)

			// Query for publicly accessible Redis Caches
			query := `
				resources
				| where type =~ 'Microsoft.Cache/Redis'
				| extend publicNetworkAccess = tolower(properties.publicNetworkAccess)
				| extend sku = properties.sku.name
				| extend enableNonSslPort = properties.enableNonSslPort
				| extend minimumTlsVersion = properties.minimumTlsVersion
				| extend hostname = properties.hostName
				| extend subnetId = properties.subnetId
				| extend firewallRules = array_length(properties.firewallRules)
				| where isempty(subnetId)
				| where publicNetworkAccess != 'disabled'
				| extend hasOpenFirewall = firewallRules == 0 or
					properties.firewallRules has '0.0.0.0' and 
					properties.firewallRules has '255.255.255.255'
				| where hasOpenFirewall
				| project
					id,
					name,
					type,
					location,
					publicNetworkAccess,
					sku,
					enableNonSslPort,
					minimumTlsVersion,
					hostname
				| order by name asc
            `

			queryOpts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			var details = make(map[string]*RedisCacheDetail)

			err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return fmt.Errorf("unexpected response data type")
				}

				logger.Debug("Processing Redis Caches",
					slog.Int("count", len(rows)),
					slog.String("subscription", subscription))

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					id := helpers.SafeGetString(item, "id")
					if _, exists := details[id]; !exists {
						detail := &RedisCacheDetail{
							ID:                  id,
							Name:                helpers.SafeGetString(item, "name"),
							Type:                helpers.SafeGetString(item, "type"),
							Location:            helpers.SafeGetString(item, "location"),
							PublicNetworkAccess: helpers.SafeGetString(item, "publicNetworkAccess"),
							Sku:                 helpers.SafeGetString(item, "sku"),
							EnableNonSslPort:    helpers.SafeGetBool(item, "enableNonSslPort"),
							MinimalTlsVersion:   helpers.SafeGetString(item, "minimalTlsVersion"),
							HostName:            helpers.SafeGetString(item, "hostName"),
						}

						details[id] = detail
					}
				}
				return nil
			})

			if err != nil {
				logger.Error("Failed to query Redis Caches",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			if len(details) > 0 {
				var detailsList []*RedisCacheDetail
				for _, detail := range details {
					detailsList = append(detailsList, detail)
				}

				message.Info("Found %d publicly accessible Redis Caches in subscription %s", len(detailsList), subscription)
				select {
				case out <- detailsList:
				case <-ctx.Done():
					return
				}
			} else {
				message.Info("No publicly accessible Redis Caches found in subscription %s", subscription)
			}
		}
	}()

	return out
}
