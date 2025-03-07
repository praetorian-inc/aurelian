package recon

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsCloudControlGetResource struct {
	modules.BaseModule
}

var AwsCloudControlGetResourceOptions = []*types.Option{
	&options.AwsRegionOpt,
	&options.AwsResourceTypeOpt,
	&options.AwsResourceIdOpt,
}

var AwsCloudControlGetResourceMetadata = modules.Metadata{
	Id:          "get",
	Name:        "Cloud Control Get Resource",
	Description: "Get a resource in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var AwsCloudControlGetResourceOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewConsoleProvider,
}

func NewAwsCloudControlGetResource(opts []*types.Option) (<-chan types.EnrichedResourceDescription, stages.Stage[types.EnrichedResourceDescription, types.EnrichedResourceDescription], error) {
	pipeline, err := stages.ChainStages[types.EnrichedResourceDescription, types.EnrichedResourceDescription](
		stages.AwsCloudControlGetResource,
	)

	if err != nil {
		return nil, nil, err
	}

	resource := types.EnrichedResourceDescription{
		Region:     options.GetOptionByName(options.AwsRegionOpt.Name, opts).Value,
		TypeName:   options.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value,
		AccountId:  "",
		Identifier: options.GetOptionByName(options.AwsResourceIdOpt.Name, opts).Value,
	}

	return stages.Generator([]types.EnrichedResourceDescription{resource}), pipeline, nil
}
