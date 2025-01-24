package reconsaas

import (
	"context"
	"fmt"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type MiscDockerDump struct {
	modules.BaseModule
}

var SaasDockerDumpOptions = []*types.Option{
	options.WithDescription(
		*options.WithRequired(options.PathOpt, false),
		"Path to list of container images"),
	options.WithRequired(options.ImageOpt, false),
	options.WithRequired(options.DockerUserOpt, false),
	options.WithRequired(options.DockerPasswordOpt, false),
}

var SaasDockerDumpOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var SaasDockerDumpMetadata = modules.Metadata{
	Id:          "docker-dump",
	Name:        "Docker Container Dumper",
	Description: "Extract the file contents of a Docker container.",
	Platform:    modules.Universal,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.None,
	References:  []string{},
}

func NewSaasDockerDump(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.DockerExtractorStage,
	)

	if err != nil {
		return nil, nil, err
	}

	if options.GetOptionByName(options.PathOpt.Name, opts).Value == "" && options.GetOptionByName(options.ImageOpt.Name, opts).Value == "" {
		return nil, nil, fmt.Errorf("missing required option: %s or %s", options.PathOpt.Name, options.ImageOpt.Name)
	}

	var in <-chan string
	if options.GetOptionByName(options.ImageOpt.Name, opts).Value != "" {
		in = stages.Generator([]string{options.GetOptionByName(options.ImageOpt.Name, opts).Value})
	}
	if options.GetOptionByName(options.PathOpt.Name, opts).Value != "" {
		in = stages.FileGenerator(context.TODO(), opts, stages.Generator([]string{options.GetOptionByName(options.PathOpt.Name, opts).Value}))
	}

	return in, pipeline, nil
}
