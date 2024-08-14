package reconaws

import (
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
		if resourceType == "cloudformation" {
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
		} else if resourceType == "ec2" {
			// incomplete. there is a bug in GetResourcesCloudCOntrol
			runListResources := modules.NewRun()
			ListResourcesCloudControl(m, runListResources, helpers.CCEc2Instance)
			ec2ListData := <-runListResources.Data
			resourceData := ec2ListData.UnmarshalListData()
			regionToIdentifiers := helpers.MapIdentifiersByRegions(resourceData.ResourceDescriptions)
			runGetResources := modules.NewRun()
			GetResourcesCloudControl(m, runGetResources, helpers.CCEc2Instance, regionToIdentifiers)
			close(runGetResources.Data)

		}
	}

	wg.Wait()
	return nil
}

// There is soemthign wrong here
// TODO to fix - i think it's something to do with the channels not being closed properly
func GetResourcesCloudControl(m *AwsFindSecrets, runGetResources modules.Run, ccResource string, regionToIdentifiers map[string][]string) error {

	AwsResourceTypeOpt := o.Option{
		Name:  o.AwsResourceTypeOpt.Name,
		Value: ccResource,
	}
	for region, identifiers := range regionToIdentifiers {
		AwsRegionOpt := o.Option{
			Name:  o.AwsRegionOpt.Name,
			Value: region,
		}
		for _, identifier := range identifiers {
			AwsResourceIdOpt := o.Option{
				Name:  o.AwsResourceIdOpt.Name,
				Value: identifier,
			}
			run := modules.NewRun()
			options := m.Options
			options = append(options, &AwsResourceTypeOpt, &AwsRegionOpt, &AwsResourceIdOpt)
			getResource, err := NewAwsCloudControlGetResource(options, run)
			if err != nil {
				return err
			}
			err = getResource.Invoke()
			if err != nil {
				return err
			}
			runGetResources.Data <- m.MakeResult(run.Data)

		}
	}
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
