package recon

// import (
// 	"fmt"

// 	"github.com/praetorian-inc/nebula/internal/helpers"
// 	"github.com/praetorian-inc/nebula/modules"
// 	"github.com/praetorian-inc/nebula/modules/options"
// )

// type AwsListAllResources struct {
// 	modules.BaseModule
// }

// var AwsListAllResourcesRequiredOptions = []*types.Option{}

// var AwsListAllResourcesMetadata = modules.Metadata{
// 	Id:          "list-all",
// 	Name:        "List All Resources",
// 	Description: "List all resources in an AWS account.",
// 	Platform:    modules.AWS,
// 	Authors:     []string{"Praetorian"},
// 	OpsecLevel:  modules.Moderate,
// 	References:  []string{},
// }

// func NewAwsListAllResources(options []*types.Option, run types.Run) (modules.Module, error) {
// 	var m AwsListAllResources
// 	m.SetMetdata(AwsListAllResourcesMetadata)
// 	m.Run = run

// 	m.Options = options

// 	return &m, nil
// }

// func (m *AwsListAllResources) Invoke() error {
// 	defer close(m.Run.Output)

// 	sumOpt := m.GetOptionByName(options.AwsSummaryServicesOpt.Name)
// 	if sumOpt.Value == "true" {
// 		run := types.Run{Output: make(chan types.Result)}
// 		sum, err := NewAwsSummary(m.Options, run)
// 		if err != nil {
// 			return err
// 		}
// 		err = sum.Invoke()
// 		if err != nil {
// 			return err
// 		}

// 		fmt.Println("1")
// 		services := <-run.Output
// 		fmt.Println(services)
// 		fmt.Println("2")
// 		close(run.Output)
// 	} else {
// 		regions, error := helpers.EnabledRegions(m.GetOptionByName(options.AwsProfileOpt.Name).Value)
// 		if error != nil {
// 			return error
// 		}

// 		for _, region := range regions {
// 			run := types.Run{Output: make(chan types.Result)}
// 			awsRegionOpt := types.Option{
// 				Name:  options.AwsRegionOpt.Name,
// 				Value: region,
// 			}
// 			options := append(m.Options, &awsRegionOpt)
// 			getResources, err := NewAwsCloudControlListResources(options, run)
// 			if err != nil {
// 				return err
// 			}

// 			err = getResources.Invoke()
// 			if err != nil {
// 				return err
// 			}

// 			resources := <-run.Output
// 			close(run.Output)

// 			m.Run.Output <- resources
// 		}
// 	}

// 	m.Run.Output <- m.MakeResult("")
// 	return nil
// }
