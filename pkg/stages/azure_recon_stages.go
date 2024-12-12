package stages

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Stage for getting Azure environment summary
func GetAzureEnvironmentSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *helpers.AzureEnvironmentDetails {
	out := make(chan *helpers.AzureEnvironmentDetails)

	go func() {
		defer close(out)
		for subscription := range in {
			env, err := helpers.GetEnvironmentDetails(ctx, subscription, opts)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get environment details for subscription %s: %v", subscription, err))
				continue
			}
			out <- env
		}
	}()

	return out
}
