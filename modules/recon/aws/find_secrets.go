package recon

import (
	"log/slog"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsFindSecrets struct {
	modules.BaseModule
}

var AwsFindSecretsOptions = []*types.Option{
	&options.AwsRegionsOpt,
	&options.AwsFindSecretsResourceType,
	&options.OutputOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
}

var AwsFindSecretsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets",
	Name:        "AWS Find Secrets",
	Description: "This module will enumerate resources in AWS and attempt to find secrets using Nosey Parker.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsFindSecrets(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsFindSecretsStage,
		stages.NoseyParkerEnumeratorStage,
		//stages.AggregateOutput[types.EnrichedResourceDescription], // TODO this is a hack until we can write files to the approporate location again
	)

	if err != nil {
		return nil, nil, err
	}

	_, err = helpers.FindBinary(types.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value)
	if err != nil {
		message.Error("Nosey Parker binary not found in path")
		return nil, nil, err
	}

	rtype := types.GetOptionByName(options.AwsFindSecretsResourceType.Name, opts).Value

	if rtype == "ALL" {
		slog.Info("Loading public resources recon module for all types")
		return stages.Generator(SecretTypes), pipeline, nil
	} else {
		slog.Info("Loading public resources recon module for types: " + rtype)
		in := stages.ParseTypes(types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value)
		return in, pipeline, nil
	}
}

// You can probalby not use runGetResources and instead just pass in m.Run.Data
// However, if you want to do any processing later then you wouldn't be able to if youre passing directly to m.Run.Data
// func GetResourcesCloudControl(m *AwsFindSecrets, runGetResources types.Run, ccResource string, regionToIdentifiers map[string][]string) error {
// 	defer close(runGetResources.Output)
// 	wg := new(sync.WaitGroup)
// 	// Need to add resource type to options
// 	AwsResourceTypeOpt := types.Option{
// 		Name:  o.AwsResourceTypeOpt.Name,
// 		Value: ccResource,
// 	}
// 	for region, identifiers := range regionToIdentifiers {
// 		// need to add region to the run options
// 		AwsRegionOpt := types.Option{
// 			Name:  o.AwsRegionOpt.Name,
// 			Value: region,
// 		}
// 		for _, identifier := range identifiers {

// 			wg.Add(1)
// 			go func(r string, i string) error {
// 				defer wg.Done()
// 				// need to add the specific resource ID to the options
// 				AwsResourceIdOpt := types.Option{
// 					Name:  o.AwsResourceIdOpt.Name,
// 					Value: i,
// 				}
// 				run := modules.NewRun()
// 				// need to create a deep copy or else you'll end up editing m.Options which will mess up the other goroutines that are running
// 				options := o.CreateDeepCopyOfOptions(m.Options)
// 				// add it all to options
// 				options = append(options, &AwsResourceTypeOpt, &AwsRegionOpt, &AwsResourceIdOpt)
// 				getResource, err := NewAwsCloudControlGetResource(options, run)
// 				if err != nil {
// 					return err
// 				}
// 				err = getResource.Invoke()
// 				if err != nil {
// 					return err
// 				}
// 				runData := <-run.Output
// 				runGetResources.Output <- runData
// 				return nil
// 			}(region, identifier)
// 		}
// 	}
// 	wg.Wait()
// 	return nil
// }

var SecretTypes = []string{
	"AWS::CloudFormation::Stack",
	"AWS::Lambda::Function",
	"AWS::EC2::Instance",
}
