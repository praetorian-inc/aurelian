package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/nebula/stages"
)

type AwsExpandActions struct {
	modules.BaseModule
}

var AwsExpandActionsOptions = []*options.Option{
	&options.AwsActionOpt,
}

var AwsExpandActionOutputProvders = []func(options []*options.Option) modules.OutputProvider{
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

// func NewAwsExpandActions(options []*options.Option, run modules.Run) (modules.Module, error) {
// 	var m AwsExpandActions
// 	m.SetMetdata(AwsExpandActionsMetadata)
// 	m.Run = run
// 	m.Options = options
// 	m.ConfigureOutputProviders(AwsExpandActionOutputProvders)

// 	return &m, nil
// }

func NewAwsExpandActions(opts []*options.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsExpandActionsStage,
	)

	if err != nil {
		return nil, nil, err
	}

	action := options.GetOptionByName(options.AwsActionOpt.Name, opts).Value

	return stages.Generator([]string{action}), pipeline, nil
}
