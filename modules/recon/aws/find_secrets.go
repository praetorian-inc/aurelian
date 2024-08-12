package reconaws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
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

	var stacksData modules.Result
	profile := o.GetOptionByName("profile", m.Options).Value
	resourceType := o.GetOptionByName("secret-resource-type", m.Options)
	regionsOpt := o.GetOptionByName("regions", m.Options)
	regions, err := helpers.ParseRegionsOption(regionsOpt.Value, profile)
	if err != nil {
		return err
	}

	for _, region := range regions {
		cfg, err := helpers.GetAWSCfg(region, profile)
		if err != nil {
			return err
		}
		if resourceType.Value == "cloudformation" {
			client := cloudformation.NewFromConfig(cfg)
			// get Template TODO -  need to turn this into a gofunc

			run := modules.NewRun()
			ListCloudFormationStacks(region, profile, run)
			stacksData = <-run.Data
			resourceData := stacksData.UnmarshalListData()
			identifiers := resourceData.GetIdentifiers()
			regionToArnIdentifiers, err := MapArnByRegions(identifiers)
			if err != nil {
				return err
			}
			getCFTemplates2(client, m, regionToArnIdentifiers[region], region)

			// describe Templates
			describeCFStacks(m)

		}
	}

	return nil
}

func describeCFStacks(m *AwsFindSecrets) {
}

// This function uses the CloudControl List Resources module to grab all the stack names
func ListCloudFormationStacks(region, profile string, run modules.Run) error {

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

func getCFTemplates2(client *cloudformation.Client, m *AwsFindSecrets, regionToArnIdentifiers []helpers.ArnIdentifier, region string) error {
	wg := new(sync.WaitGroup)
	resourceType := o.GetOptionByName("secret-resource-type", m.Options).Value
	for _, arn := range regionToArnIdentifiers {
		wg.Add(1)
		go func() error {
			defer wg.Done()
			result, err := client.GetTemplate(context.TODO(), &cloudformation.GetTemplateInput{
				StackName: aws.String(arn.ARN),
			})
			if err != nil {
				return err
			}
			stackName, err := extractCFStackName(arn.Resource)
			if err != nil {
				return err
			}
			filepath := helpers.CreateFilePath(string(m.Platform), resourceType, region, arn.AccountID, stackName)
			templateBody := *result.TemplateBody
			m.Run.Data <- m.MakeResultCustomFilename(templateBody, filepath)
			return nil
		}()
	}
	wg.Wait()
	return nil
}

// This function is used to retrieve all the cloudformation templates given a map of region to a list of ArnIdentifiers
func getCFTemplates(m *AwsFindSecrets, regionToArnIdentifiers map[string][]helpers.ArnIdentifier) error {
	wg := new(sync.WaitGroup)
	resourceType := o.GetOptionByName("secret-resource-type", m.Options)
	profile := o.GetOptionByName("profile", m.Options)
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
				stackName, err := extractCFStackName(arn.Resource)
				if err != nil {
					return err
				}
				filepath := helpers.CreateFilePath(string(m.Platform), resourceType.Value, region, arn.AccountID, stackName)
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
func extractCFStackName(resource string) (string, error) {
	stackParts := strings.Split(resource, "/")
	if len(stackParts) < 2 || stackParts[0] != "stack" {
		return "", fmt.Errorf("invalid Cloudformation Resource: %s", resource)
	}
	// The stack name is the second part
	return stackParts[1], nil
}

func MapArnByRegions(identifiers []string) (map[string][]helpers.ArnIdentifier, error) {
	regionToArnIdentifiers := make(map[string][]helpers.ArnIdentifier)
	for _, identifier := range identifiers {
		arn, err := helpers.NewArn(identifier)
		if err != nil {
			return nil, err
		}
		regionToArnIdentifiers[arn.Region] = append(regionToArnIdentifiers[arn.Region], arn)
	}
	return regionToArnIdentifiers, nil
}
