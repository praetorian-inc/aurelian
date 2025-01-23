package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
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
		AwsFindSecretsStage,
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

func AwsFindSecretsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AwsFindSecretsStage")
	out := make(chan types.NpInput)
	go func() {
		defer close(out)

		for rtype := range in {
			var pl stages.Stage[string, types.NpInput]
			var err error

			switch rtype {
			case "AWS::Lambda::Function":
				pl, err = stages.ChainStages[string, types.NpInput](
					stages.CloudControlListResources,
					stages.EnrichedResourceDescriptionToNpInput,
				)
			case "AWS::EC2::Instance":
				pl, err = stages.ChainStages[string, types.NpInput](
					stages.CloudControlListResources,
					stages.EnrichedResourceDescriptionToNpInput,
				)
			case "AWS::CloudFormation::Stack":
				pl, err = stages.ChainStages[string, types.NpInput](
					stages.CloudControlListResources,
					stages.EnrichedResourceDescriptionToNpInput,
				)
			default:
				logger.Error("Unknown resource type: " + rtype)
				continue
			}

			logger.Info(fmt.Sprintf("Processing resource type %s", rtype))
			if err != nil {
				logger.Error("Failed to " + rtype + " create pipeline: " + err.Error())
				continue
			}
			for s := range pl(ctx, opts, stages.Generator([]string{rtype})) {
				out <- s
			}
		}
	}()

	return out
}

// func (m *AwsFindSecrets) Invoke() error {

// 	defer close(m.Run.Output)
// 	wg := new(sync.WaitGroup)
// 	profile := types.GetOptionByName("profile", m.Options).Value
// 	regionsOpt := types.GetOptionByName("regions", m.Options)
// 	resourceTypesOpt := types.GetOptionByName("secret-resource-types", m.Options).Value
// 	resourceTypes := helpers.ParseSecretsResourceType(resourceTypesOpt)
// 	regions, err := helpers.ParseRegionsOption(regionsOpt.Value, profile)
// 	if err != nil {
// 		return err
// 	}

// 	for _, resourceType := range resourceTypes {

// 		switch resourceType {
// 		case "cloudformation":

// 			run := modules.NewRun()
// 			ListResourcesCloudControl(m, run, helpers.CCCloudFormationStack)
// 			stacksData := <-run.Output
// 			resourceData := stacksData.UnmarshalListData()
// 			identifiers := resourceData.GetIdentifiers()
// 			regionToArnIdentifiers, err := helpers.MapArnByRegions(identifiers)
// 			if err != nil {
// 				return err
// 			}
// 			wg.Add(1)
// 			go func() {
// 				defer wg.Done()
// 				GetCFTemplates(m, regionToArnIdentifiers)
// 			}()
// 			wg.Add(1)
// 			go func() {
// 				defer wg.Done()
// 				DescribeCFStacks(m, regions)
// 			}()

// 		case "ec2":

// 			runListResources := modules.NewRun()
// 			ListResourcesCloudControl(m, runListResources, helpers.CCEc2Instance)
// 			ec2ListData := <-runListResources.Output
// 			resourceData := ec2ListData.UnmarshalListData()
// 			regionToIdentifiers := helpers.MapIdentifiersByRegions(resourceData.ResourceDescriptions)

// 			// runGetResources will be used to accept all the data from each getResource run.
// 			runGetResources := modules.NewRun()
// 			go func() {
// 				GetResourcesCloudControl(m, runGetResources, helpers.CCEc2Instance, regionToIdentifiers)
// 			}()
// 			for data := range runGetResources.Output {
// 				// TODO need to work on processing data to extract userdata and base64 decode
// 				fmt.Println(data)
// 				m.Run.Output <- data
// 			}
// 		default:
// 			name, err := helpers.ResolveCommonResourceTypes(resourceType)
// 			if !err {
// 				return fmt.Errorf("unable to resolve resource type %s", resourceType)
// 			}

// 			runListResources := modules.NewRun()
// 			ListResourcesCloudControl(m, runListResources, name)
// 			res := modules.NewRun()
// 			ctx := context.WithValue(context.Background(), "awsProfile", profile)

// 			go func() {
// 				GetResources(ctx, runListResources.Output, res.Output)
// 			}()

// 			for data := range res.Output {
// 				fmt.Println(data)
// 				m.Run.Output <- data
// 			}
// 		}
// 	}

// 	wg.Wait()
// 	return nil
// }

func GetCFTemplatesStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.Result {
	out := make(chan types.Result)
	go func() {
		// defer close(out)
		// for data := range in {
		// 	cfg, err := helpers.GetAWSCfg(data.Region, types.GetOptionByName("profile", opts).Value)
		// 	if err != nil {
		// 		logger.Error(err.Error())
		// 		continue
		// 	}

		// 	cf := cloudformation.NewFromConfig(cfg)
		// 	template, err := cf.GetTemplate(ctx, &cloudformation.GetTemplateInput{
		// 		StackName: &data.Identifier,
		// 	})

		// 	if err != nil {
		// 		logger.Error(err.Error())
		// 		continue
		// 	}

		// 	result := types.NewResult(m.Platform, m.Id, templateBody, types.WithFilename(filepath))

		// 	out <- data
		// }
	}()

	return out
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
