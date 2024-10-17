package recon

import (
	"strconv"
	"time"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsCloudControlListResources struct {
	modules.BaseModule
}

var AwsCloudControlListResourcesOptions = []*types.Option{
	&o.AwsRegionsOpt,
	&o.AwsResourceTypeOpt,
	types.SetDefaultValue(
		*types.SetRequired(
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
	References: []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	},
}

var AwsCloudControlListResourcesOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	//op.NewConsoleProvider,
}

func NewAwsCloudControlListResources(opts []*types.Option) (<-chan string, stages.Stage[string, []types.EnrichedResourceDescription], error) {
	pipeline, err := stages.ChainStages[string, []types.EnrichedResourceDescription](
		stages.CloudControlListResources,
		stages.AggregateOutput[types.EnrichedResourceDescription],
	)

	if err != nil {
		return nil, nil, err
	}

	resourceType := types.GetOptionByName(o.AwsResourceTypeOpt.Name, opts).Value

	return stages.Generator([]string{resourceType}), pipeline, nil
}
