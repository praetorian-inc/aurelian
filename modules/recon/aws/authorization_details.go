package recon

import (
	"strings"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsAuthorizationDetails struct {
	modules.BaseModule
	AccountId string
}

var AwsAuthorizationDetailsOptions = []*types.Option{
	&o.AwsProfileListOpt,
}

var AwsAuthorizationDetailsMetadata = modules.Metadata{
	Id:          "authorization-details",
	Name:        "Authorization Details",
	Description: "Get authorization details in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var AwsAuthorizationDetailsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
}

func NewAwsAuthorizationDetailsModel(opts []*types.Option) (modules.Module, error) {
	in, pl, err := NewAwsAuthorizationDetails(opts)
	if err != nil {
		return nil, err
	}

	return &AwsAuthorizationDetails{
		BaseModule: modules.BaseModule{
			Metadata:        AwsAuthorizationDetailsMetadata,
			Options:         AwsAuthorizationDetailsOptions,
			OutputProviders: modules.RenderOutputProviders(AwsAuthorizationDetailsOutputProviders, opts),
			In:              in,
			Stage:           pl,
		},
	}, nil

}

func NewAwsAuthorizationDetails(opts []*types.Option) (<-chan string, stages.Stage[string, []byte], error) {
	profileList := options.GetOptionByName(o.AwsProfileListOpt.Name, opts).Value
	profile := options.GetOptionByName(o.AwsProfileOpt.Name, opts).Value
	var profiles []string

	if profileList == "" {
		profiles = []string{profile}
	} else {
		profiles = strings.Split(profileList, ",")
	}

	pipeline, err := stages.ChainStages[string, []byte](
		stages.AwsGetAccountAuthorizationDetailsStage,
	)

	if err != nil {
		return nil, nil, err
	}

	return stages.Generator(profiles), pipeline, nil
}
