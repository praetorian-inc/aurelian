package reconaws

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	o "github.com/praetorian-inc/nebula/modules/options"
)

/*
Add the follwoing to the init() function in cmd/registry.go to register the module:

RegisterModule(awsReconCmd, recon.AwsFindSecretsMetadata, recon.AwsFindSecretsOptions, awsCommonOptions, recon.NewAwsFindSecrets)
*/

type AwsFindSecrets struct {
	modules.BaseModule
}

var AwsFindSecretsOptions = []*options.Option{
	&o.AwsRegionsOpt,
	&o.AwsFindSecretsResourceType,
	o.SetDefaultValue(
		*o.SetRequired(
			o.OutputOpt, false),
		AwsFindSecretsMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)),
}

var AwsFindSecretsOutputProviders = []func(options []*options.Option) modules.OutputProvider{
	op.NewFileProvider,
}

var AwsFindSecretsMetadata = modules.Metadata{
	Id:          "find-secrets", // this will be the CLI command name
	Name:        "find-secrets",
	Description: "this module will search multiple different known places for potential secrets ",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsFindSecrets(options []*options.Option, run modules.Run) (modules.Module, error) {
	return &AwsFindSecrets{
		BaseModule: modules.BaseModule{
			Metadata:        AwsFindSecretsMetadata,
			Options:         options,
			Run:             run,
			OutputProviders: modules.RenderOutputProviders(AwsFindSecretsOutputProviders, options),
		},
	}, nil
}

func (m *AwsFindSecrets) Invoke() error {

	defer close(m.Run.Data)
	wg := new(sync.WaitGroup)
	profile := o.GetOptionByName("profile", m.Options).Value
	regionsOpt := o.GetOptionByName("regions", m.Options)
	resourceTypesOpt := o.GetOptionByName("secret-resource-types", m.Options).Value
	resourceTypes := helpers.ParseSecretsResourceType(resourceTypesOpt)
	regions, err := helpers.ParseRegionsOption(regionsOpt.Value, profile)
	if err != nil {
		return err
	}

	for _, resourceType := range resourceTypes {
		switch resourceType {
		case "cloudformation":
			run := modules.NewRun()
			ListResourcesCloudControl(m, run, helpers.CCCloudFormationStack)
			stacksData := <-run.Data
			resourceData := stacksData.UnmarshalListData()
			identifiers := resourceData.GetIdentifiers()
			regionToArnIdentifiers, err := helpers.MapArnByRegions(identifiers)
			if err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				GetCFTemplates(m, regionToArnIdentifiers)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				DescribeCFStacks(m, regions)
			}()
		case "ec2":
			runListResources := modules.NewRun()
			ListResourcesCloudControl(m, runListResources, helpers.CCEc2Instance)
			ec2ListData := <-runListResources.Data
			resourceData := ec2ListData.UnmarshalListData()
			regionToIdentifiers := helpers.MapIdentifiersByRegions(resourceData.ResourceDescriptions)
			// runGetResources will be used to accept all the data from each getResource run.
			runGetResources := modules.NewRun()
			go func() {
				GetResourcesCloudControl(m, runGetResources, helpers.CCEc2Instance, regionToIdentifiers)
			}()
			for data := range runGetResources.Data {
				// TODO need to work on processing data to extract userdata and base64 decode
				fmt.Println(data)
				m.Run.Data <- data
			}
		case "ecs":
			runListResources := modules.NewRun()
			ListResourcesCloudControl(m, runListResources, helpers.CCEcs)
			ecsListData := <-runListResources.Data
			resourceData := ecsListData.UnmarshalListData()
			regionToIdentifiers := helpers.MapIdentifiersByRegions(resourceData.ResourceDescriptions)
			runGetResources := modules.NewRun()

			go func() {
				GetResourcesCloudControl(m, runGetResources, helpers.CCEcs, regionToIdentifiers)
			}()

			for data := range runGetResources.Data {
				fmt.Println(data)
				m.Run.Data <- data
			}
		}
	}
	wg.Wait()
	return nil
}

// You can probalby not use runGetResources and instead just pass in m.Run.Data
// However, if you want to do any processing later then you wouldn't be able to if youre passing directly to m.Run.Data
func GetResourcesCloudControl(m *AwsFindSecrets, runGetResources modules.Run, ccResource string, regionToIdentifiers map[string][]string) error {
	defer close(runGetResources.Data)
	wg := new(sync.WaitGroup)
	// Need to add resource type to options
	AwsResourceTypeOpt := o.Option{
		Name:  o.AwsResourceTypeOpt.Name,
		Value: ccResource,
	}
	for region, identifiers := range regionToIdentifiers {
		// need to add region to the run options
		AwsRegionOpt := o.Option{
			Name:  o.AwsRegionOpt.Name,
			Value: region,
		}
		for _, identifier := range identifiers {
			wg.Add(1)
			go func(r string, i string) error {
				defer wg.Done()
				// need to add the specific resource ID to the options
				AwsResourceIdOpt := o.Option{
					Name:  o.AwsResourceIdOpt.Name,
					Value: i,
				}
				run := modules.NewRun()
				// need to create a deep copy or else you'll end up editing m.Options which will mess up the other goroutines that are running
				options := o.CreateDeepCopyOfOptions(m.Options)
				// add it all to options
				options = append(options, &AwsResourceTypeOpt, &AwsRegionOpt, &AwsResourceIdOpt)
				getResource, err := NewAwsCloudControlGetResource(options, run)
				if err != nil {
					return err
				}
				err = getResource.Invoke()
				if err != nil {
					return err
				}
				runData := <-run.Data
				runGetResources.Data <- runData
				return nil
			}(region, identifier)
		}
	}
	wg.Wait()
	return nil
}

// This uses the cloud_control_list_resources module to get all the cloudformation stacks
func ListResourcesCloudControl(m *AwsFindSecrets, run modules.Run, ccResource string) error {
	AwsResourceTypeOpt := o.Option{
		Name:  o.AwsResourceTypeOpt.Name,
		Value: ccResource,
	}
	options := m.Options
	options = append(options, &AwsResourceTypeOpt)
	listResources, err := NewAwsCloudControlListResources(options, run)
	if err != nil {
		return err
	}
	err = listResources.Invoke()
	if err != nil {
		return err
	}
	return nil
}
