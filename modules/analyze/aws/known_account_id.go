package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
)

type KnownAccountID struct {
	modules.BaseModule
}

var KnownAccountIDOptions = []*o.Option{
	&o.AwsAccountIdOpt,
}

var KnownAccountIDMetadata = modules.Metadata{
	Id:          "known-account-id",
	Name:        "Known Account ID",
	Description: "This module takes an AWS account ID and returns returns information about it if known.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://github.com/rupertbg/aws-public-account-ids/tree/master",
	},
}

var KnownAccountIDOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

func NewKnownAccountID(opts []*options.Option) (<-chan string, stages.Stage[string, stages.AwsKnownAccount], error) {
	pipeline, err := stages.ChainStages[string, stages.AwsKnownAccount](
		stages.AwsKnownAccountIdStage,
	)

	if err != nil {
		return nil, nil, err
	}

	accountID := options.GetOptionByName(o.AwsAccountIdOpt.Name, opts).Value

	return stages.Generator([]string{accountID}), pipeline, nil
}
