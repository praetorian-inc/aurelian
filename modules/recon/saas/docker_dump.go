package reconsaas

import (
	"fmt"
	"os"
	"strings"

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
		*options.WithRequired(options.FileNameOpt, false),
		"File of container image names to dump"),
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

func NewSaasDockerDump(opts []*types.Option) (<-chan stages.ImageContext, stages.Stage[stages.ImageContext, string], error) {
	pipeline, err := stages.ChainStages[stages.ImageContext, string](
		stages.DockerPullStage,
		stages.DockerSaveStage,
	)

	if err != nil {
		return nil, nil, err
	}

	if options.GetOptionByName(options.FileNameOpt.Name, opts).Value == "" && options.GetOptionByName(options.ImageOpt.Name, opts).Value == "" {
		return nil, nil, fmt.Errorf("missing required option: %s or %s", options.FileNameOpt.Name, options.ImageOpt.Name)
	}

	var in <-chan stages.ImageContext

	// handle single image argument
	if options.GetOptionByName(options.ImageOpt.Name, opts).Value != "" {
		in = stages.Generator[stages.ImageContext]([]stages.ImageContext{stages.DockerOpts2ImageContext(opts)})
	}

	// handle file list of images
	if options.GetOptionByName(options.FileNameOpt.Name, opts).Value != "" {
		filePath := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
		fileContents, err := os.ReadFile(filePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %v", err)
		}

		lines := strings.Split(string(fileContents), "\n")
		var imageContexts []stages.ImageContext
		for _, line := range lines {
			if line == "" {
				continue
			}
			newOpts := []*types.Option{
				options.WithValue(options.ImageOpt, line),
				options.GetOptionByName(options.DockerUserOpt.Name, opts),
				options.GetOptionByName(options.DockerPasswordOpt.Name, opts),
			}
			imageContexts = append(imageContexts, stages.DockerOpts2ImageContext(newOpts))
		}
		in = stages.Generator[stages.ImageContext](imageContexts)
	}

	return in, pipeline, nil
}
