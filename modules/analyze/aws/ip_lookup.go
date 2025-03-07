package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

/*
Add the follwoing to the init() function in cmd/registry.go to register the module:

*/

type AwsIPLookup struct {
	modules.BaseModule
}

var AwsIPLookupOptions = []*types.Option{
	&options.IPOpt,
}

var AwsIPLookupOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsIPLookupMetadata = modules.Metadata{
	Id:          "iplookup", // this will be the CLI command name
	Name:        "AWS IP Lookup",
	Description: "Search AWS IP ranges for a specific IP address.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsIPLookup(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsIpLookupStage,
	)

	if err != nil {
		return nil, nil, err
	}

	ip := options.GetOptionByName(options.IPOpt.Name, opts).Value

	return stages.Generator([]string{ip}), pipeline, nil
}
