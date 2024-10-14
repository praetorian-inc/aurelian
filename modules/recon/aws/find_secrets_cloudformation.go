package recon

// import (
// 	"context"
// 	"fmt"
// 	"strings"
// 	"sync"

// 	"github.com/aws/aws-sdk-go-v2/aws/arn"
// 	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
// 	"github.com/aws/aws-sdk-go/aws"
// 	"github.com/praetorian-inc/nebula/internal/helpers"
// 	"github.com/praetorian-inc/nebula/modules"
// 	o "github.com/praetorian-inc/nebula/modules/options"
// )

// func DescribeCFStacks(m *AwsFindSecrets, regions []string) error {
// 	resourceType := types.GetOptionByName("secret-resource-types", m.Options)
// 	profile := types.GetOptionByName("profile", m.Options)
// 	command := "describeStacks"
// 	wg := new(sync.WaitGroup)

// 	for _, region := range regions {
// 		wg.Add(1)
// 		go func() error {
// 			defer wg.Done()
// 			cfg, err := helpers.GetAWSCfg(region, profile.Value)
// 			if err != nil {
// 				return err
// 			}
// 			client := cloudformation.NewFromConfig(cfg)
// 			result, err := client.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{})
// 			if err != nil {
// 				return err
// 			}
// 			stacks := result.Stacks
// 			for _, stack := range stacks {
// 				stackArn, err := helpers.NewArn(*stack.StackId)
// 				stackName := *stack.StackName
// 				if err != nil {
// 					return err
// 				}
// 				filepath := helpers.CreateFilePath(string(m.Platform), resourceType.Value, stackArn.AccountID, command, region, stackName)
// 				m.Run.Output <- m.MakeResult(stack, types.WithFilename(filepath))
// 			}
// 			return nil
// 		}()
// 	}
// 	wg.Wait()
// 	return nil
// }

// // This function uses the CloudControl List Resources module to grab all the stack names for the passed in region
// func ListCloudFormationStacksSingleRegion(region, profile string, run types.Run) error {

// 	AwsResourceTypeOpt := types.Option{
// 		Name:  o.AwsResourceTypeOpt.Name,
// 		Value: "AWS::CloudFormation::Stack",
// 	}
// 	AwsRegionsOpt := types.Option{
// 		Name:  o.AwsRegionsOpt.Name,
// 		Value: region,
// 	}
// 	AwsProfileOpt := types.Option{
// 		Name:  o.AwsProfileOpt.Name,
// 		Value: profile,
// 	}
// 	OutputOpt := types.Option{
// 		Name:  o.OutputOpt.Name,
// 		Value: o.OutputOpt.Value,
// 	}
// 	var options []*types.Option
// 	options = append(options, &AwsResourceTypeOpt, &AwsProfileOpt, &AwsRegionsOpt, &OutputOpt)
// 	listResources, err := NewAwsCloudControlListResources(options, run)
// 	if err != nil {
// 		return err
// 	}
// 	err = listResources.Invoke()
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// // This function is used to retrieve all the cloudformation templates given a map of region to a list of ArnIdentifiers
// // This is much faster pass in the map containing all regions rather than passing in only a list of only a region because the goroutine would have to wait for each region to finish before moving forward.
// func GetCFTemplates(m *AwsFindSecrets, regionToArnIdentifiers map[string][]arn.ARN) error {
// 	wg := new(sync.WaitGroup)
// 	resourceType := types.GetOptionByName("secret-resource-types", m.Options)
// 	profile := types.GetOptionByName("profile", m.Options)
// 	command := "getTemplate"
// 	for region, arns := range regionToArnIdentifiers {
// 		cfg, err := helpers.GetAWSCfg(region, profile.Value)
// 		if err != nil {
// 			return err
// 		}
// 		client := cloudformation.NewFromConfig(cfg)

// 		for _, a := range arns {
// 			wg.Add(1)
// 			go func() error {
// 				defer wg.Done()
// 				result, err := client.GetTemplate(context.TODO(), &cloudformation.GetTemplateInput{
// 					StackName: aws.String(a.String()),
// 				})
// 				if err != nil {
// 					return err
// 				}
// 				stackName, err := ExtractCFStackName(a.Resource)
// 				if err != nil {
// 					return err
// 				}
// 				filepath := helpers.CreateFilePath(string(m.Platform), resourceType.Value, a.AccountID, command, region, stackName)
// 				templateBody := *result.TemplateBody

// 				m.Run.Output <- types.NewResult(m.Platform, m.Id, templateBody, types.WithFilename(filepath))
// 				return nil
// 			}()
// 		}
// 	}
// 	wg.Wait()
// 	return nil
// }

// // Resource names for cloudformation stacks are quite long and contain additional identifiers. This just pulls out only the stack name
// func ExtractCFStackName(resource string) (string, error) {
// 	stackParts := strings.Split(resource, "/")
// 	if len(stackParts) < 2 || stackParts[0] != "stack" {
// 		return "", fmt.Errorf("invalid Cloudformation Resource: %s", resource)
// 	}
// 	// The stack name is the second part
// 	return stackParts[1], nil
// }
