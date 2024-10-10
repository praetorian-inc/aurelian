package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
)

/*
Add the follwoing to the init() function in cmd/registry.go to register the module:

*/

type AwsIPLookup struct {
	modules.BaseModule
}

var AwsIPLookupOptions = []*options.Option{
	&options.IPOpt,
}

var AwsIPLookupOutputProviders = []func(options []*options.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

var AwsIPLookupMetadata = modules.Metadata{
	Id:          "iplookup", // this will be the CLI command name
	Name:        "IPLookup",
	Description: "Search AWS IP ranges for a specific IP address.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsIPLookup(opts []*options.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsIpLookupStage,
	)

	if err != nil {
		return nil, nil, err
	}

	ip := options.GetOptionByName(options.IPOpt.Name, opts).Value

	return stages.Generator([]string{ip}), pipeline, nil
}
