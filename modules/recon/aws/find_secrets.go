package recon

import (
	"log/slog"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsFindSecrets struct {
	modules.BaseModule
}

var AwsFindSecretsOptions = []*types.Option{
	&options.AwsRegionsOpt,
	&options.AwsFindSecretsResourceType,
	&options.OutputOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
}

var AwsFindSecretsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets",
	Name:        "AWS Find Secrets",
	Description: "This module will enumerate resources in AWS and attempt to find secrets using Nosey Parker.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsFindSecrets(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsFindSecretsStage,
		stages.NoseyParkerEnumeratorStage,
	)

	if err != nil {
		return nil, nil, err
	}

	_, err = helpers.FindBinary(options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value)
	if err != nil {
		message.Error("Nosey Parker binary not found in path")
		return nil, nil, err
	}

	rtype := options.GetOptionByName(options.AwsFindSecretsResourceType.Name, opts).Value

	if strings.ToLower(rtype) == "all" {
		slog.Info("Loading public resources recon module for all types")
		return stages.Generator(options.FindSecretsTypes), pipeline, nil
	} else {
		slog.Info("Loading public resources recon module for types: " + rtype)
		in := stages.SplitByComma(options.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value)
		return in, pipeline, nil
	}
}
