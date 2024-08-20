package reconaws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type AwsCloudControlGetResource struct {
	modules.BaseModule
}

var AwsCloudControlGetResourceOptions = []*options.Option{
	&options.AwsRegionOpt,
	&options.AwsResourceTypeOpt,
	&options.AwsResourceIdOpt,
}

var AwsCloudControlGetResourceMetadata = modules.Metadata{
	Id:          "get",
	Name:        "Cloud Control Get Resource",
	Description: "Get a resource in an AWS account using Cloud Control API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var AwsCloudControlGetResourceOutputProviders = []func(options []*options.Option) modules.OutputProvider{
	op.NewFileProvider,
}

func NewAwsCloudControlGetResource(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsCloudControlGetResource
	m.SetMetdata(AwsCloudControlGetResourceMetadata)
	m.Run = run

	fileNameOpt := o.FileNameOpt
	fileNameOpt.Value = m.Metadata.Id + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".json"
	options = append(options, &fileNameOpt)
	m.Options = options
	m.ConfigureOutputProviders(AwsCloudControlGetResourceOutputProviders)

	return &m, nil
}

func (m *AwsCloudControlGetResource) Invoke() error {
	region := m.GetOptionByName(options.AwsRegionOpt.Name).Value
	rtype := m.GetOptionByName(options.AwsResourceTypeOpt.Name).Value
	id := m.GetOptionByName(options.AwsResourceIdOpt.Name).Value

	cfg, err := helpers.GetAWSCfg(region, m.GetOptionByName(options.AwsProfileOpt.Name).Value)
	if err != nil {
		return err
	}
	accountId, err := helpers.GetAccountId(cfg)
	if err != nil {
		fmt.Println(err)
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
	filepath := helpers.CreateFilePath(string(m.Platform), helpers.CloudControlTypeNames[rtype], accountId, "get-resource", region, id)

	m.Run.Data <- m.MakeResult(res, modules.WithFilename(filepath))
	close(m.Run.Data)

	return nil
}
