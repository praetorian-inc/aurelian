package reconaws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type AwsAuthorizationDetails struct {
	modules.BaseModule
}

var AwsAuthorizationDetailsRequiredOptions = []*options.Option{}

var AwsAuthorizationDetailsMetadata = modules.Metadata{
	Id:          "authorization-details",
	Name:        "Authorization Details",
	Description: "Get authorization details in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsAuthorizationDetails(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsAuthorizationDetails
	m.SetMetdata(AwsAuthorizationDetailsMetadata)
	m.Run = run
	m.Options = options

	return &m, nil
}

func (m *AwsAuthorizationDetails) Invoke() error {
	config, err := helpers.GetAWSCfg("")
	if err != nil {
		return err
	}
	client := iam.NewFromConfig(config)
	output, err := client.GetAccountAuthorizationDetails(context.TODO(), &iam.GetAccountAuthorizationDetailsInput{})
	if err != nil {
		return err
	}

	m.Run.Data <- m.MakeResult(output)

	return nil
}
