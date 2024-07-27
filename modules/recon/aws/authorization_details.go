package reconaws

import (
	"context"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type AwsAuthorizationDetails struct {
	modules.BaseModule
}

var AwsAuthorizationDetailsRequiredOptions = []*o.Option{}

var AwsAuthorizationDetailsMetadata = modules.Metadata{
	Id:          "authorization-details",
	Name:        "Authorization Details",
	Description: "Get authorization details in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var AwsAuthorizationDetailsOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewFileProvider,
}

func NewAwsAuthorizationDetails(options []*o.Option, run modules.Run) (modules.Module, error) {
	var m AwsAuthorizationDetails
	//m.SetMetdata(AwsAuthorizationDetailsMetadata)
	m.Metadata = AwsAuthorizationDetailsMetadata
	m.Run = run

	// TODO: this should be an optional parameter and we can use this as the default
	fileNameOpt := o.FileNameOpt
	fileNameOpt.Value = m.Metadata.Id + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".json"
	options = append(options, &fileNameOpt)

	m.Options = options
	m.ConfigureOutputProviders(AwsAuthorizationDetailsOutputProviders)

	return &m, nil
}

func (m *AwsAuthorizationDetails) Invoke() error {
	config, err := helpers.GetAWSCfg("", m.GetOptionByName(o.AwsProfileOpt.Name).Value)
	if err != nil {
		return err
	}
	client := iam.NewFromConfig(config)
	output, err := client.GetAccountAuthorizationDetails(context.TODO(), &iam.GetAccountAuthorizationDetailsInput{})
	if err != nil {
		return err
	}

	m.Run.Data <- m.MakeResult(output)
	close(m.Run.Data)

	return nil
}
