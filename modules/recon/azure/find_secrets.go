// Package reconaz implements Azure reconnaissance modules
package reconaz

import (
	"context"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Supported resource types for secret scanning
var AzureFindSecretsTypes = []string{
	"Microsoft.Compute/virtualMachines",
	// Add more resource types here as handlers are implemented
	"ALL",
}

// Module metadata
var AzureFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets",
	Name:        "Find Secrets",
	Description: "Enumerate Azure resources and find secrets using Nosey Parker",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

// Module options
var AzureFindSecretsOptions = []*types.Option{
	&types.Option{
		Name:        "subscription",
		Short:       "s",
		Description: "Azure subscription ID or 'all' for all accessible subscriptions",
		Required:    true,
		Type:        types.String,
		Value:       "",
	},
	&types.Option{
		Name:        "resource-types",
		Short:       "t",
		Description: "Azure resource types to scan - " + strings.Join(AzureFindSecretsTypes, ", "),
		Required:    true,
		Type:        types.String,
		Value:       "",
		ValueList:   AzureFindSecretsTypes,
	},
	&types.Option{
		Name:        "workers",
		Short:       "w",
		Description: "Number of concurrent workers for processing resources",
		Required:    false,
		Type:        types.Int,
		Value:       "5",
	},
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
}

// Output providers
var AzureFindSecretsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

func NewAzureFindSecrets(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	// Check for Nosey Parker binary
	_, err := helpers.FindBinary(options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value)
	if err != nil {
		message.Error("Nosey Parker binary not found in path")
		return nil, nil, err
	}

	// Create the processing pipeline
	pipeline, err := stages.ChainStages[string, string](
		stages.AzureGetTargetedResourcesStage,
		stages.NoseyParkerEnumeratorStage,
	)

	if err != nil {
		return nil, nil, err
	}

	// Handle subscription input
	subscriptionsChan := make(chan string)
	subscriptionOpt := options.GetOptionByName("subscription", opts).Value

	go func() {
		defer close(subscriptionsChan)

		if strings.EqualFold(subscriptionOpt, "all") {
			ctx := context.WithValue(context.Background(), "metadata", AzureFindSecretsMetadata)
			subscriptions, err := helpers.ListSubscriptions(ctx, opts)
			if err != nil {
				message.Error("Failed to list subscriptions: %v", err)
				return
			}

			for _, sub := range subscriptions {
				subscriptionsChan <- sub
			}
		} else {
			subscriptionsChan <- subscriptionOpt
		}
	}()

	return subscriptionsChan, pipeline, nil
}
