package recon

import (
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AwsPublicResourcesOptions = []*types.Option{
	&options.AwsRegionsOpt,
	&options.AwsResourceTypeOpt,
}

var AwsPublicResourcesOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsPublicResourcesMetadata = modules.Metadata{
	Id:          "public-resources", // this will be the CLI command name
	Name:        "Public Resources",
	Description: "Return a list of public resources in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsPublicResources(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {

	pipeline, err := stages.ChainStages[string, string](
		stages.Echo[string],
		stages.AwsPublicResources,
	)

	if err != nil {
		return nil, nil, err
	}

	rtype := types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value

	if rtype == "ALL" {
		logs.ConsoleLogger().Info("Loading public resources recon module for all types")
		return stages.Generator(PublicTypes), pipeline, nil
	} else {
		logs.ConsoleLogger().Info("Loading public resources recon module for types: " + rtype)
		in := stages.ParseTypes(types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value)
		return in, pipeline, nil
	}
}

var PublicTypes = []string{
	"AWS::EC2::Instance",
	"AWS::ECR::Repository",
	"AWS::ECR::PublicRepository",
	"AWS::Lambda::Function",
	"AWS::Lambda::LayerVersion",
	// "AWS::RDS::DBCluster",
	"AWS::S3::Bucket",
	"AWS::ServerlessRepo::Application",
}
