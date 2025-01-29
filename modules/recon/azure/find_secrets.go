package reconaz

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// List of supported resource types
var AzureSupportedTypes = []string{
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
		options.AzureResourceTypesOpt,
		"Azure resource types to scan. Currently supported types: "+strings.Join(AzureSupportedTypes, ", "),
	),
	&options.AzureSubscriptionOpt,
	&options.AzureWorkerCountOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
}

// Output providers
var AzureFindSecretsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

func NewAzureFindSecrets(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	ctx := context.WithValue(context.Background(), "metadata", AzureFindSecretsMetadata)
	logger := logs.NewStageLogger(ctx, opts, "AzureFindSecrets")

	// Check for Nosey Parker binary
	_, err := helpers.FindBinary(options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value)
	if err != nil {
		logger.Error("Nosey Parker binary not found in path")
		return nil, nil, err
	}

	// Get subscriptions list
	subscriptionOpt := options.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value
	var subscriptions []string

	if strings.EqualFold(subscriptionOpt, "all") {
		subs, err := helpers.ListSubscriptions(ctx, opts)
		if err != nil {
			logger.Error("Failed to list subscriptions", slog.String("error", err.Error()))
			return nil, nil, err
		}
		subscriptions = subs
		logger.Info("Found subscriptions to scan", slog.Int("count", len(subscriptions)))
	} else {
		subscriptions = []string{subscriptionOpt}
	}

	// Get resource types
	resourceType := options.GetOptionByName(options.AzureResourceTypesOpt.Name, opts).Value
	var resourceTypes []string
	if strings.EqualFold(resourceType, "all") {
		logger.Info("Loading secrets scanner for all resource types")
		for _, rt := range AzureSupportedTypes {
			if !strings.EqualFold(rt, "all") {
				resourceTypes = append(resourceTypes, rt)
			}
		}
	} else {
		logger.Info("Loading secrets scanner for type", slog.String("type", resourceType))
		resourceTypes = append(resourceTypes, resourceType)
	}

	// Create input channel
	inputChan := make(chan string)
	go func() {
		defer close(inputChan)
		for _, rt := range resourceTypes {
			// Create config for this resource type
			config := stages.ScanConfig{
				ResourceType:  rt,
				Subscriptions: subscriptions,
			}
			// Marshal to JSON string
			if configStr, err := json.Marshal(config); err == nil {
				select {
				case inputChan <- string(configStr):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Create the main pipeline chain
	mainPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureFindSecretsStage,
	)
	if err != nil {
		return nil, nil, err
	}

	// Create the complete pipeline with NoseyParker
	fullPipeline, err := stages.ChainStages[string, string](
		func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
			return mainPipeline(ctx, opts, in)
		},
		stages.NoseyParkerEnumeratorStage,
		stages.ToString[string],
	)
	if err != nil {
		return nil, nil, err
	}

	return inputChan, fullPipeline, nil
}
