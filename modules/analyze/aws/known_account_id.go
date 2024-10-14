package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type KnownAccountID struct {
	modules.BaseModule
}

var KnownAccountIDOptions = []*types.Option{
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

var KnownAccountIDOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

func NewKnownAccountID(opts []*types.Option) (<-chan string, stages.Stage[string, stages.AwsKnownAccount], error) {
	pipeline, err := stages.ChainStages[string, stages.AwsKnownAccount](
		stages.AwsKnownAccountIdStage,
	)

	if err != nil {
		return nil, nil, err
	}

	accountID := types.GetOptionByName(o.AwsAccountIdOpt.Name, opts).Value

	return stages.Generator([]string{accountID}), pipeline, nil
}
