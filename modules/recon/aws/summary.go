package recon

import (
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsSummary struct {
	modules.BaseModule
}

var AwsSummaryOptions = []*types.Option{}

var AwsSummaryOutputProviders = []func(options []*types.Option) types.OutputProvider{}

var AwsSummaryMetadata = modules.Metadata{
	Id:          "summary",
	Name:        "AWS Summary",
	Description: "Use cost explorer to summarize the services and regions in use.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

// func NewAwsSummary(options []*types.Option, run types.Run) (modules.Module, error) {
// 	return &AwsSummary{
// 		BaseModule: modules.BaseModule{
// 			Metadata:        AwsSummaryMetadata,
// 			Options:         options,
// 			Run:             run,
// 			OutputProviders: modules.RenderOutputProviders(nil, options),
// 		}}, nil
// }

// func (m *AwsSummary) Invoke() error {
// 	cfg, err := helpers.GetAWSCfg("", m.GetOptionByName(options.AwsProfileOpt.Name).Value, opts)

// 	if err != nil {
// 		fmt.Println("Failed to load AWS config:", err)
// 		return err
// 	}

// 	// Get all regions
// 	serviceRegions, err := utils.GetServiceAndRegions(cfg)
// 	if err != nil {
// 		fmt.Println("Failed to get regions:", err)
// 		return err
// 	}

// 	// Iterate over each region
// 	for service, regions := range serviceRegions {
// 		fmt.Println("Service:", service)
// 		for _, region := range regions {
// 			fmt.Println("  Region:", region)
// 			if region == "NoRegion" {
// 				continue
// 			}
// 		}

// 	}
// 	m.Run.Output <- m.MakeResult(serviceRegions)
// 	close(m.Run.Output)
// 	return nil
// }

// func ListResources(cfg aws.Config, rtype string) ([]*cloudcontrol.ListResourcesOutput, error) {
// 	fmt.Printf("%v\n", rtype)
// 	cc := cloudcontrol.NewFromConfig(cfg)
// 	params := &cloudcontrol.ListResourcesInput{}
// 	var results []*cloudcontrol.ListResourcesOutput

// 	params.TypeName = &rtype

// 	for {
// 		res, err := cc.ListResources(context.TODO(), params)

// 		if err != nil {
// 			fmt.Println("Error listing resources:", err)
// 			return nil, err
// 		}

// 		fmt.Printf("desc: %v\n", res.ResourceDescriptions)
// 		fmt.Printf("Next: %v\n", res.NextToken)
// 		results = append(results, res)

// 		if res.NextToken == nil {
// 			break
// 		}
// 	}

// 	return results, nil
// }
