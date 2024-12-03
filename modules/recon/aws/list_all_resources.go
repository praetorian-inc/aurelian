package recon

import (
	"strconv"
	"time"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Module options
var AwsListAllResourcesOptions = []*types.Option{
	&options.AwsRegionsOpt,
	&options.AwsResourceTypeOpt,
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		AwsListAllResourcesMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)+".json"),
}

// Module metadata
var AwsListAllResourcesMetadata = modules.Metadata{
	Id:          "list-all",
	Name:        "List All Resources",
	Description: "List all resources in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

// Output providers
var AwsListAllResourcesOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
}

// Module constructor
func NewAwsListAllResources(opts []*types.Option) (<-chan string, stages.Stage[string, []types.EnrichedResourceDescription], error) {
	// Create pipeline using existing stages
	pipeline, err := stages.ChainStages[string, []types.EnrichedResourceDescription](
		stages.CloudControlListResources,                          // Lists resources
		stages.CloudControlGetResource,                            // Gets detailed info for each resource
		stages.AggregateOutput[types.EnrichedResourceDescription], // Collects all results
	)

	if err != nil {
		return nil, nil, err
	}

	// Handle resource type input
	rtype := types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value

	// If ALL is specified, list all supported resource types
	if rtype == "ALL" {
		return stages.Generator(GetSupportedResourceTypes()), pipeline, nil
	}

	// Otherwise use specified resource type
	return stages.ParseTypes(types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value), pipeline, nil
}

// Helper function to get supported resource types
func GetSupportedResourceTypes() []string {
	return []string{
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::IAM::Role",
		"AWS::RDS::DBInstance",
		"AWS::DynamoDB::Table",
		// Add more resource types as needed
	}
}

// import (
// 	"fmt"

// 	"github.com/praetorian-inc/nebula/internal/helpers"
// 	"github.com/praetorian-inc/nebula/modules"
// 	"github.com/praetorian-inc/nebula/modules/options"
// )

// type AwsListAllResources struct {
// 	modules.BaseModule
// }

// var AwsListAllResourcesRequiredOptions = []*types.Option{}

// var AwsListAllResourcesMetadata = modules.Metadata{
// 	Id:          "list-all",
// 	Name:        "List All Resources",
// 	Description: "List all resources in an AWS account.",
// 	Platform:    modules.AWS,
// 	Authors:     []string{"Praetorian"},
// 	OpsecLevel:  modules.Moderate,
// 	References:  []string{},
// }

// func NewAwsListAllResources(options []*types.Option, run types.Run) (modules.Module, error) {
// 	var m AwsListAllResources
// 	m.SetMetdata(AwsListAllResourcesMetadata)
// 	m.Run = run

// 	m.Options = options

// 	return &m, nil
// }

// func (m *AwsListAllResources) Invoke() error {
// 	defer close(m.Run.Output)

// 	sumOpt := m.GetOptionByName(options.AwsSummaryServicesOpt.Name)
// 	if sumOpt.Value == "true" {
// 		run := types.Run{Output: make(chan types.Result)}
// 		sum, err := NewAwsSummary(m.Options, run)
// 		if err != nil {
// 			return err
// 		}
// 		err = sum.Invoke()
// 		if err != nil {
// 			return err
// 		}

// 		fmt.Println("1")
// 		services := <-run.Output
// 		fmt.Println(services)
// 		fmt.Println("2")
// 		close(run.Output)
// 	} else {
// 		regions, error := helpers.EnabledRegions(m.GetOptionByName(options.AwsProfileOpt.Name).Value)
// 		if error != nil {
// 			return error
// 		}

// 		for _, region := range regions {
// 			run := types.Run{Output: make(chan types.Result)}
// 			awsRegionOpt := types.Option{
// 				Name:  options.AwsRegionOpt.Name,
// 				Value: region,
// 			}
// 			options := append(m.Options, &awsRegionOpt)
// 			getResources, err := NewAwsCloudControlListResources(options, run)
// 			if err != nil {
// 				return err
// 			}

// 			err = getResources.Invoke()
// 			if err != nil {
// 				return err
// 			}

// 			resources := <-run.Output
// 			close(run.Output)

// 			m.Run.Output <- resources
// 		}
// 	}

// 	m.Run.Output <- m.MakeResult("")
// 	return nil
// }
