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
	"Microsoft.Web/sites",
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
	options.WithDescription(
		options.AzureSubscriptionOpt,
		"Azure subscription ID or 'all' for all accessible subscriptions",
	),
	options.WithDescription(
		options.AzureResourceTypesOpt,
		"Azure resource types to scan - "+strings.Join(options.AzureResourceTypesOpt.ValueList, ", "),
	),
	options.WithDefaultValue(
		options.AzureWorkerCountOpt,
		"5",
	),
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
	subscriptionOpt := options.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value

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
