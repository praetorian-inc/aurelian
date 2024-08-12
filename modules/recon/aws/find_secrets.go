package reconaws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go/aws"
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
	allSupportedTypes := []string{"cloudformation"}
	var resourceTypes []string
	defer close(m.Run.Data)
	wg := new(sync.WaitGroup)
	profile := o.GetOptionByName("profile", m.Options).Value
	regionsOpt := o.GetOptionByName("regions", m.Options)
	resourceTypesOpt := o.GetOptionByName("secret-resource-types", m.Options).Value
	if resourceTypesOpt == "ALL" {
		resourceTypes = allSupportedTypes
	} else {
		resourceTypes = strings.Split(resourceTypesOpt, ",")
	}
	regions, err := helpers.ParseRegionsOption(regionsOpt.Value, profile)
	if err != nil {
		return err
	}

	for _, resourceType := range resourceTypes {
		if resourceType == "cloudformation" {
			run := modules.NewRun()
			ListCloudFormationStacks(m, run)
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
		}

	}

	wg.Wait()
	return nil
}

func DescribeCFStacks(m *AwsFindSecrets, regions []string) error {
	resourceType := o.GetOptionByName("secret-resource-types", m.Options)
	profile := o.GetOptionByName("profile", m.Options)
	command := "describeStacks"
	wg := new(sync.WaitGroup)

	for _, region := range regions {
		wg.Add(1)
		go func() error {
			defer wg.Done()
			cfg, err := helpers.GetAWSCfg(region, profile.Value)
			if err != nil {
				return err
			}
			client := cloudformation.NewFromConfig(cfg)
			result, err := client.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{})
			if err != nil {
				return err
			}
			stacks := result.Stacks
			for _, stack := range stacks {
				stackArn, err := helpers.NewArn(*stack.StackId)
				stackName := *stack.StackName
				if err != nil {
					return err
				}
				filepath := helpers.CreateFilePath(string(m.Platform), resourceType.Value, stackArn.AccountID, command, region, stackName)
				m.Run.Data <- m.MakeResultCustomFilename(stack, filepath)
			}
			return nil
		}()
	}
	wg.Wait()
	return nil
}

// This function uses the CloudControl List Resources module to grab all the stack names for the passed in region
func ListCloudFormationStacksSingleRegion(region, profile string, run modules.Run) error {

	AwsResourceTypeOpt := options.Option{
		Name:  options.AwsResourceTypeOpt.Name,
		Value: "AWS::CloudFormation::Stack",
	}
	AwsRegionsOpt := options.Option{
		Name:  options.AwsRegionsOpt.Name,
		Value: region,
	}
	AwsProfileOpt := options.Option{
		Name:  options.AwsProfileOpt.Name,
		Value: profile,
	}
	OutputOpt := options.Option{
		Name:  options.OutputOpt.Name,
		Value: options.OutputOpt.Value,
	}
	var options []*options.Option
	options = append(options, &AwsResourceTypeOpt, &AwsProfileOpt, &AwsRegionsOpt, &OutputOpt)
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

// This uses the cloud_control_list_resources module to get all the cloudformation stacks
func ListCloudFormationStacks(m *AwsFindSecrets, run modules.Run) error {

	AwsResourceTypeOpt := o.Option{
		Name:  o.AwsResourceTypeOpt.Name,
		Value: "AWS::CloudFormation::Stack",
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

// This function is used to retrieve all the cloudformation templates given a map of region to a list of ArnIdentifiers
func GetCFTemplates(m *AwsFindSecrets, regionToArnIdentifiers map[string][]helpers.ArnIdentifier) error {
	wg := new(sync.WaitGroup)
	resourceType := o.GetOptionByName("secret-resource-types", m.Options)
	profile := o.GetOptionByName("profile", m.Options)
	command := "getTemplate"
	for region, arns := range regionToArnIdentifiers {
		cfg, err := helpers.GetAWSCfg(region, profile.Value)
		if err != nil {
			return err
		}
		client := cloudformation.NewFromConfig(cfg)

		for _, arn := range arns {
			wg.Add(1)
			go func() error {
				defer wg.Done()
				result, err := client.GetTemplate(context.TODO(), &cloudformation.GetTemplateInput{
					StackName: aws.String(arn.ARN),
				})
				if err != nil {
					return err
				}
				stackName, err := ExtractCFStackName(arn.Resource)
				if err != nil {
					return err
				}
				filepath := helpers.CreateFilePath(string(m.Platform), resourceType.Value, arn.AccountID, command, region, stackName)
				templateBody := *result.TemplateBody
				m.Run.Data <- m.MakeResultCustomFilename(templateBody, filepath)
				return nil
			}()
		}
	}
	wg.Wait()
	return nil
}

// Resource names for cloudformation stacks are quite long and contain additional identifiers. This just pulls out only the stack name
func ExtractCFStackName(resource string) (string, error) {
	stackParts := strings.Split(resource, "/")
	if len(stackParts) < 2 || stackParts[0] != "stack" {
		return "", fmt.Errorf("invalid Cloudformation Resource: %s", resource)
	}
	// The stack name is the second part
	return stackParts[1], nil
}
