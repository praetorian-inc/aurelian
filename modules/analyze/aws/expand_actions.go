package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsExpandActions struct {
	modules.BaseModule
}

var AwsExpandActionsOptions = []*types.Option{
	&options.AwsActionOpt,
}

var AwsExpandActionOutputProvders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsExpandActionsMetadata = modules.Metadata{
	Id:          "expand-actions",
	Name:        "AWS Expand Actions",
	Description: "This module takes a wildcard action and returns a list of all possible actions that match the wildcard.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsExpandActions(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsExpandActionsStage,
	)

	if err != nil {
		return nil, nil, err
	}

	action := options.GetOptionByName(options.AwsActionOpt.Name, opts).Value

	return stages.Generator([]string{action}), pipeline, nil
}
