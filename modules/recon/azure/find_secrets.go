package reconaz

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets",
	Name:        "Find Azure Secrets",
	Description: "Enumerate Azure VMs and Function Apps to find secrets using Nosey Parker and Azure Resource Graph",
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

	// Create input channel with subscription config
	inputChan := make(chan string)
	go func() {
		defer close(inputChan)
		config := helpers.ScanConfig{
			Subscriptions: subscriptions,
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

	// Create parallel pipelines for VMs and Function Apps that merge into NoseyParker
	vmPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureListVMsStage,
		stages.AzureVMSecretsStage,
	)
	if err != nil {
		return nil, nil, err
	}

	functionPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureListFunctionAppsStage,
		stages.AzureFunctionAppSecretsStage,
	)
	if err != nil {
		return nil, nil, err
	}

	// Final pipeline that combines VM and Function App scanning
	pipeline, err := stages.ChainStages[string, string](
		stages.ParallelStages(vmPipeline, functionPipeline), // Run VM and Function App scanning in parallel
		stages.NoseyParkerEnumeratorStage,                   // Process extracted content with Nosey Parker
		stages.ToString[string],                             // Convert to string output
	)

	if err != nil {
		return nil, nil, err
	}

	return inputChan, pipeline, nil
}
