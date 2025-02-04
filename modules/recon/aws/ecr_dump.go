package recon

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsEcrDump struct {
	modules.BaseModule
}

var AwsEcrDumpOptions = []*types.Option{
	options.WithRequired(options.AwsRegionsOpt, false),
	options.WithRequired(options.DockerUserOpt, false),
	options.WithRequired(options.DockerPasswordOpt, false),
	options.WithDefaultValue(options.DockerExtractOpt, "true"),
	&options.OutputOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
	options.WithDefaultValue(options.NoseyParkerScanOpt, "true"),
}

var AwsEcrDumpOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsEcrDumpMetadata = modules.Metadata{
	Id:          "ecr-dump", // this will be the CLI command name
	Name:        "ECR Dump",
	Description: "Dump ECR container filesystems to disk",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsEcrDump(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	priv, err := stages.ChainStages[types.EnrichedResourceDescription, stages.ImageContext](
		stages.AwsEcrListImages,
		stages.AwsEcrLoginStage,
	)

	if err != nil {
		return nil, nil, err
	}

	public, err := stages.ChainStages[types.EnrichedResourceDescription, stages.ImageContext](
		stages.AwsEcrPublicListLatestImages,
		stages.AwsEcrPublicLoginStage,
	)

	if err != nil {
		return nil, nil, err
	}

	// only run Nosey Parker if the the scan opt is true
	npPipeline := []stages.Stage[string, string]{}
	if options.GetOptionByName(options.NoseyParkerScanOpt.Name, opts).Value == "true" {
		p, err := stages.ChainStages[string, string](
			stages.DockerExtractToNPStage,
			stages.NoseyParkerEnumeratorStage,
			stages.NoseyParkerSummarizeStage,
		)

		if err != nil {
			return nil, nil, err
		}

		npPipeline = append(npPipeline, p)
	} else {
		npPipeline = []stages.Stage[string, string]{stages.NopStage[string]}
	}

	pipeline, err := stages.ChainStages[string, string](
		stages.AwsCloudControlListResources,
		stages.Tee[types.EnrichedResourceDescription, stages.ImageContext](
			// private repos
			[]stages.Stage[types.EnrichedResourceDescription, stages.ImageContext]{
				priv,
			},

			// public repos
			[]stages.Stage[types.EnrichedResourceDescription, stages.ImageContext]{
				public,
			},
		),
		stages.DockerPullStage,
		stages.DockerSaveStage,
		stages.Tee(
			[]stages.Stage[string, string]{stages.DockerExtractToFSStage},
			npPipeline,
		),
	)

	if err != nil {
		return nil, nil, err
	}

	return stages.Generator([]string{
		"AWS::ECR::Repository",
		"AWS::ECR::PublicRepository",
	}), pipeline, nil
}
