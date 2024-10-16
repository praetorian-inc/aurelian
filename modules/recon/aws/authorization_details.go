package recon

import (
	"strconv"
	"time"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsAuthorizationDetails struct {
	modules.BaseModule
	AccountId string
}

var AwsAuthorizationDetailsOptions = []*types.Option{}

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
	op.NewFileProvider,
}

func NewAwsAuthorizationDetails(opts []*types.Option) (<-chan string, stages.Stage[string, []byte], error) {

	// TODO: this should be an optional parameter and we can use this as the default
	// TODO: default should have the account id in the file name
	fileNameOpt := o.FileNameOpt

	fileNameOpt.Value = AwsAuthorizationDetailsMetadata.Id + "-" + strconv.FormatInt(time.Now().Unix(), 10) + "-gaad.json"
	opts = append(opts, &fileNameOpt)

	pipeline, err := stages.ChainStages[string, []byte](
		stages.GetAccountAuthorizationDetailsStage,
	)

	if err != nil {
		return nil, nil, err
	}

	return stages.Generator([]string{"foo"}), pipeline, nil
}
