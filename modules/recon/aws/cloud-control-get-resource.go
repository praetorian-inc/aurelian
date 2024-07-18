package reconaws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type AwsCloudControlGetResource struct {
	modules.BaseModule
}

var AwsCloudControlGetResourceRequiredOptions = []*options.Option{
	&options.AwsRegionOpt,
	&options.AwsResourceTypeOpt,
	&options.AwsResourceIdOpt,
}

var AwsCloudControlGetResourceMetadata = modules.Metadata{
	Id:          "cloud-control-get-resource",
	Name:        "Cloud Control Get Resource",
	Description: "Get a resource in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsCloudControlGetResource(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsCloudControlGetResource
	m.SetMetdata(AwsCloudControlGetResourceMetadata)
	m.Run = run
	for _, opt := range AwsCloudControlGetResourceRequiredOptions {
		err := m.ValidateOptions(*opt, options)
		if err != nil {
			return nil, err
		}
	}

	m.Options = options

	return &m, nil
}

func (m *AwsCloudControlGetResource) Invoke() error {
	region := m.GetOptionByName(options.AwsRegionOpt.Name).Value
	rtype := m.GetOptionByName(options.AwsResourceTypeOpt.Name).Value
	id := m.GetOptionByName(options.AwsResourceIdOpt.Name).Value

	cfg, err := helpers.GetAWSCfg(region)
	if err != nil {
		return err
	}

	cc := cloudcontrol.NewFromConfig(cfg)

	params := &cloudcontrol.GetResourceInput{
		Identifier: &id,
		TypeName:   &rtype,
	}

	res, err := cc.GetResource(context.Background(), params)
	if err != nil {
		return err
	}

	m.Run.Data <- m.MakeResult(res)

	return nil
}
