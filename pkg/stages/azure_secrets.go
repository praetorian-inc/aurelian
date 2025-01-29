package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// ScanConfig holds the configuration for a resource type scan
type ScanConfig struct {
	ResourceType  string   `json:"resourceType"`
	Subscriptions []string `json:"subscriptions"`
}

// AzureFindSecretsStage performs secret scanning of Azure resources
func AzureFindSecretsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFindSecretsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for configStr := range in {
			var config ScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			logger.Info("Processing resource type", slog.String("type", config.ResourceType))

			var successCount, failureCount int
			totalSubs := len(config.Subscriptions)

			for _, subscription := range config.Subscriptions {
				logger.Info("Scanning subscription",
					slog.String("subscription", subscription),
					slog.String("resourceType", config.ResourceType))

				var pl Stage[string, types.NpInput]
				var err error

				switch config.ResourceType {
				case "Microsoft.Compute/virtualMachines":
					pl, err = ChainStages[string, types.NpInput](
						AzureVMListResourcesStage,
						AzureVMScanSecretsStage,
					)

				case "Microsoft.Web/sites":
					logger.Info("Function App scanning not yet implemented")
					continue

				default:
					logger.Error(fmt.Sprintf("Unknown resource type: %s", config.ResourceType))
					continue
				}

				if err != nil {
					logger.Error(fmt.Sprintf("Failed to create pipeline for %s: %v", config.ResourceType, err))
					continue
				}

				// Create subscription channel
				subChan := make(chan string, 1)
				subChan <- subscription
				close(subChan)

				// Process results
				resultCount := 0
				hasError := false

				for result := range pl(ctx, opts, subChan) {
					resultCount++
					select {
					case out <- result:
					case <-ctx.Done():
						return
					}
				}

				if hasError {
					failureCount++
					logger.Warn("Failed to scan subscription",
						slog.String("subscription", subscription),
						slog.String("resourceType", config.ResourceType))
				} else if resultCount > 0 {
					successCount++
					logger.Warn("Successfully scanned subscription",
						slog.String("subscription", subscription),
						slog.String("resourceType", config.ResourceType),
						slog.Int("results", resultCount))
				} else {
					logger.Info("No resources found",
						slog.String("subscription", subscription),
						slog.String("resourceType", config.ResourceType))
				}
			}

			logger.Warn("Resource type scan complete",
				slog.String("type", config.ResourceType),
				slog.Int("successCount", successCount),
				slog.Int("totalSubs", totalSubs),
				slog.Int("failureCount", failureCount))
		}
	}()

	return out
}
