package reconaws

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type AwsCloudControlListResources struct {
	modules.BaseModule
}

var AwsCloudControlListResourcesOptions = []*o.Option{
	&o.AwsRegionsOpt,
	&o.AwsResourceTypeOpt,
	o.SetDefaultValue(
		*o.SetRequired(
			o.FileNameOpt, false),
		AwsCloudControlListResourcesMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)+".json"),
}

var AwsCloudControlListResourcesMetadata = modules.Metadata{
	Id:          "list",
	Name:        "Cloud Control List Resources",
	Description: "List resources in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var AwsCloudControlListResourcesOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewFileProvider,
}

func NewAwsCloudControlListResources(options []*o.Option, run modules.Run) (modules.Module, error) {
	return &AwsCloudControlListResources{
		BaseModule: modules.BaseModule{
			Metadata:        AwsCloudControlListResourcesMetadata,
			Options:         options,
			Run:             run,
			OutputProviders: modules.RenderOutputProviders(AwsCloudControlListResourcesOutputProviders, options),
		},
	}, nil
}

func (m *AwsCloudControlListResources) Invoke() error {
	var regions = []string{}
	rtype := m.GetOptionByName(o.AwsResourceTypeOpt.Name).Value
	regionsOpt := m.GetOptionByName(o.AwsRegionsOpt.Name)
	profile := m.GetOptionByName(o.AwsProfileOpt.Name).Value
	// if regionsOpt.Value == "ALL" {
	// 	logs.ConsoleLogger().Info("Gathering enabled regions")
	// 	// TODO we should cache this
	// 	profile := m.GetOptionByName(o.AwsProfileOpt.Name).Value
	// 	fmt.Println(profile)
	// 	enabledRegions, err := helpers.EnabledRegions(profile)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	regions = enabledRegions
	// } else {
	// 	regions = []string{regionsOpt.Value}
	// }

	regions, err := helpers.ParseRegionsOption(regionsOpt.Value, profile)
	if err != nil {
		return err
	}

	results := &cloudcontrol.ListResourcesOutput{
		ResourceDescriptions: []types.ResourceDescription{},
		TypeName:             &rtype,
	}

	resultsChan := make(chan []types.ResourceDescription)

	helpers.PrintMessage("Listing resources of type " + rtype + " in regions: " + strings.Join(regions, ", "))
	for _, region := range regions {
		go func(region string) error {
			cfg, err := helpers.GetAWSCfg(region, m.GetOptionByName(o.AwsProfileOpt.Name).Value)
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

	m.Run.Data <- m.MakeResultCustomFilename(results, "test.json")
	close(m.Run.Data)

	return nil
}
