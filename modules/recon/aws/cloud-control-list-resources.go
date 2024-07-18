package reconaws

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type AwsCloudControlListResources struct {
	modules.BaseModule
}

var AwsCloudControlListResourcesRequiredOptions = []*options.Option{
	&options.AwsRegionsOpt,
	&options.AwsResourceTypeOpt,
}

var AwsCloudControlListResourcesMetadata = modules.Metadata{
	Id:          "cloud-control-list-resources",
	Name:        "Cloud Control List Resources",
	Description: "List resources in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsCloudControlListResources(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsCloudControlListResources
	m.SetMetdata(AwsCloudControlListResourcesMetadata)
	m.Run = run
	for _, opt := range AwsCloudControlListResourcesRequiredOptions {
		err := m.ValidateOptions(*opt, options)
		if err != nil {
			return nil, err
		}
	}

	m.Options = options

	return &m, nil
}

func (m *AwsCloudControlListResources) Invoke() error {
	var regions = []string{}

	rtype := m.GetOptionByName(options.AwsResourceTypeOpt.Name).Value
	regionsOpt := m.GetOptionByName(options.AwsRegionsOpt.Name)

	if regionsOpt.Value == "ALL" {
		log.Default().Println("Gathering enabled regions")
		// TODO we should cache this
		enabledRegions, err := helpers.EnabledRegions()
		if err != nil {
			return err
		}
		regions = enabledRegions
	} else {
		regions = []string{regionsOpt.Value}
	}

	results := &cloudcontrol.ListResourcesOutput{
		ResourceDescriptions: []types.ResourceDescription{},
		TypeName:             &rtype,
	}

	resultsChan := make(chan []types.ResourceDescription)

	log.Default().Printf("Listing resources of type %s in regions: %v", rtype, regions)
	for _, region := range regions {
		go func(region string) error {
			cfg, err := helpers.GetAWSCfg(region)
			if err != nil {
				return err
			}

			cc := cloudcontrol.NewFromConfig(cfg)

			params := &cloudcontrol.ListResourcesInput{
				TypeName: &rtype,
			}

			params.TypeName = &rtype

			res, err := cc.ListResources(context.Background(), params)
			if err != nil {
				resultsChan <- []types.ResourceDescription{}
				return err
			}

			// TODO results need to be enriched with region and account id
			resultsChan <- res.ResourceDescriptions

			return nil
		}(region)
	}

	for i := 0; i < len(regions); i++ {
		res := <-resultsChan
		results.ResourceDescriptions = append(results.ResourceDescriptions, res...)
	}

	close(resultsChan)

	m.Run.Data <- m.MakeResult(results)
	close(m.Run.Data)

	return nil
}
