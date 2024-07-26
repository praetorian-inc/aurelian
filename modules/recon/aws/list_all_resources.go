package reconaws

import (
	"fmt"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type AwsListAllResources struct {
	modules.BaseModule
}

var AwsListAllResourcesRequiredOptions = []*options.Option{}

var AwsListAllResourcesMetadata = modules.Metadata{
	Id:          "list-all",
	Name:        "List All Resources",
	Description: "List all resources in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsListAllResources(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsListAllResources
	m.SetMetdata(AwsListAllResourcesMetadata)
	m.Run = run

	m.Options = options

	return &m, nil
}

func (m *AwsListAllResources) Invoke() error {
	defer close(m.Run.Data)

	sumOpt := m.GetOptionByName(options.AwsSummaryServicesOpt.Name)
	if sumOpt.Value == "true" {
		run := modules.Run{Data: make(chan modules.Result)}
		sum, err := NewAwsSummary(m.Options, run)
		if err != nil {
			return err
		}
		err = sum.Invoke()
		if err != nil {
			return err
		}

		fmt.Println("1")
		services := <-run.Data
		fmt.Println(services)
		fmt.Println("2")
		close(run.Data)
	} else {
		regions, error := helpers.EnabledRegions(m.GetOptionByName(options.AwsProfileOpt.Name).Value)
		if error != nil {
			return error
		}

		for _, region := range regions {
			run := modules.Run{Data: make(chan modules.Result)}
			awsRegionOpt := options.Option{
				Name:  options.AwsRegionOpt.Name,
				Value: region,
			}
			options := append(m.Options, &awsRegionOpt)
			getResources, err := NewAwsCloudControlListResources(options, run)
			if err != nil {
				return err
			}

			err = getResources.Invoke()
			if err != nil {
				return err
			}

			resources := <-run.Data
			close(run.Data)

			m.Run.Data <- resources
		}
	}

	m.Run.Data <- m.MakeResult("")
	return nil
}
