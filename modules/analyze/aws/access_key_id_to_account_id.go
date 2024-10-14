package analyze

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsAccessKeyIdToAccountId struct {
	modules.BaseModule
}

var AwsAccessKeyIdToAccountIdOptions = []*types.Option{
	&o.AwsAccessKeyIdOpt,
}

var AwsAccessKeyIdToAccountIdOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AccessKeyIdToAccountIdMetadata = modules.Metadata{
	Id:          "access-key-id-to-account-id",
	Name:        "Access Key ID to Account ID",
	Description: "This module takes an AWS access key ID and returns the account ID associated with it.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://awsteele.com/blog/2020/09/26/aws-access-key-format.html",
		"https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489",
	},
}

func NewAccessKeyIdToAccountId(opts []*types.Option) (<-chan string, stages.Stage[string, int], error) {
	pipeline, err := stages.ChainStages[string, int](
		stages.AwsAccessKeyIdtoAccountIdStage,
	)

	if err != nil {
		return nil, nil, err
	}

	accessKeyId := types.GetOptionByName(o.AwsAccessKeyIdOpt.Name, opts).Value

	return stages.Generator([]string{accessKeyId}), pipeline, nil
}
