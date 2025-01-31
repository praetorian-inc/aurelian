package reconaz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets",
	Name:        "Find Azure Secrets",
	Description: "Enumerate Azure resources and find secrets using Nosey Parker and Azure Resource Graph",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References: []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
	},
}

var AzureFindSecretsOptions = []*types.Option{
	&options.AzureSubscriptionOpt,
	&options.AzureWorkerCountOpt,
	&options.AzureTimeoutOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
	&options.AzureResourceTypesOpt,
}

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
			return nil, nil, err
		}
		subscriptions = subs
	} else {
		subscriptions = []string{subscriptionOpt}
	}

	// Get resource types to scan
	resourceTypes := []string{}
	resourceTypeOpt := options.GetOptionByName(options.AzureResourceTypesOpt.Name, opts).Value
	if strings.ToLower(resourceTypeOpt) == "all" {
		slog.Info("Loading secrets scanning module for all supported resource types")
		for _, rtype := range options.AzureResourceTypesOpt.ValueList {
			if strings.ToLower(rtype) != "all" {
				resourceTypes = append(resourceTypes, rtype)
			}
		}
	} else {
		slog.Info("Loading secrets scanning module for resource types: " + resourceTypeOpt)
		resourceTypes = strings.Split(resourceTypeOpt, ",")
	}

	// Create input channel with subscription and resource type config
	inputChan := make(chan string)
	go func() {
		defer close(inputChan)
		config := helpers.ScanConfig{
			Subscriptions: subscriptions,
			ResourceTypes: resourceTypes,
		}
		configStr, err := json.Marshal(config)
		if err == nil {
			select {
			case inputChan <- string(configStr):
			case <-ctx.Done():
				return
			}
		}
	}()

	// Create resource type pipelines
	var resourcePipelines [][]stages.Stage[string, types.NpInput]

	for _, rtype := range resourceTypes {
		message.Info("Configuring pipeline for resource type: %s", rtype)

		switch rtype {
		case "Microsoft.Compute/virtualMachines":
			vmPipeline, err := stages.ChainStages[string, types.NpInput](
				stages.AzureListVMsStage,
				stages.AzureVMSecretsStage,
			)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create VM pipeline: %v", err))
				continue
			}
			resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{vmPipeline})

		case "Microsoft.Web/sites":
			appPipeline, err := stages.ChainStages[string, types.NpInput](
				stages.AzureListFunctionAppsStage,
				stages.AzureFunctionAppSecretsStage,
			)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create Function App pipeline: %v", err))
				continue
			}
			resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{appPipeline})

		default:
			logger.Error("Unsupported resource type: " + rtype)
		}
	}

	if len(resourcePipelines) == 0 {
		return nil, nil, fmt.Errorf("no valid resource type pipelines configured")
	}

	// Create final pipeline using Tee
	pipeline, err := stages.ChainStages[string, string](
		stages.Tee(resourcePipelines...),
		stages.NoseyParkerEnumeratorStage,
		stages.NoseyParkerSummarizeStage,
	)

	if err != nil {
		return nil, nil, err
	}

	return inputChan, pipeline, nil
}
