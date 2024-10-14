package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	ntypes "github.com/praetorian-inc/nebula/pkg/types"
)

func Ec2ListPublic(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*ntypes.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for region := range in {
				logs.ConsoleLogger().Debug("Listing public EC2 resources for " + region)
				config, _ := helpers.GetAWSCfg(region, ntypes.GetOptionByName("profile", opts).Value)
				client := ec2.NewFromConfig(config)

				ec2Input := ec2.DescribeInstancesInput{
					Filters: []types.Filter{
						{
							Name:   aws.String("network-interface.association.public-ip"),
							Values: []string{"*"}, // Filters instances with a public IP
						},
						{
							Name:   aws.String("network-interface.association.public-dns-name"),
							Values: []string{"*"}, // Filters instances with a public DNS name
						},
					},
				}
				output, err := client.DescribeInstances(ctx, &ec2Input)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					continue
				}

				for _, reservation := range output.Reservations {
					for _, instance := range reservation.Instances {
						for _, networkInterface := range instance.NetworkInterfaces {
							if networkInterface.Association != nil {
								if networkInterface.Association.PublicIp != nil {
									out <- *networkInterface.Association.PublicIp
								}
								if networkInterface.Association.PublicDnsName != nil {
									out <- *networkInterface.Association.PublicDnsName
								}
							}
						}
					}
				}

			}

		}()
		return out
	}
}

func LambdaGetFunctionUrl(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*ntypes.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for arn := range in {
				logs.ConsoleLogger().Debug("Getting URL for Lambda function: " + arn)
				region := helpers.RegionFromArn(arn)
				config, err := helpers.GetAWSCfg(region, profile)
				if err != nil {
					out <- ""
				}
				client := lambda.NewFromConfig(config)
				params := &lambda.GetFunctionUrlConfigInput{
					FunctionName: aws.String(arn),
				}
				output, err := client.GetFunctionUrlConfig(ctx, params)
				if err != nil {
					if !strings.Contains(err.Error(), "StatusCode: 404") {
						logs.ConsoleLogger().Error(err.Error())
					}
					continue
				}

				out <- *output.FunctionUrl
			}
		}()
		return out
	}
}

func ListLambdaFunctions(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*ntypes.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for region := range in {
				logs.ConsoleLogger().Debug("Listing Lambda functions " + region)
				config, err := helpers.GetAWSCfg(region, profile)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					continue
				}
				client := lambda.NewFromConfig(config)
				params := &lambda.ListFunctionsInput{}
				output, err := client.ListFunctions(ctx, params)
				if err != nil {
					out <- ""
					logs.ConsoleLogger().Error(err.Error())
				}

				for _, function := range output.Functions {
					out <- *function.FunctionArn
				}
			}
		}()
		return out
	}
}

func GetRegions(ctx context.Context, opts []*ntypes.Option) <-chan string {
	regChan := make(chan string)
	go func() {
		defer close(regChan)
		enabled, _ := helpers.EnabledRegions(ntypes.GetOptionByName("profile", opts).Value)

		for _, region := range enabled {
			regChan <- region
		}
	}()

	return regChan
}

func CloudControlListResources(ctx context.Context, opts []*ntypes.Option, rtype <-chan string) <-chan ntypes.EnrichedResourceDescription {
	out := make(chan ntypes.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing resources")
	profile := ntypes.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(ntypes.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		for _, region := range regions {
			logs.ConsoleLogger().Info("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string) {
				defer close(out)
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)
				cc := cloudcontrol.NewFromConfig(config)
				params := &cloudcontrol.ListResourcesInput{
					TypeName: &rtype,
				}
				res, err := cc.ListResources(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.ResourceDescriptions {
					out <- ntypes.EnrichedResourceDescription{
						Identifier: *resource.Identifier,
						TypeName:   rtype,
						Region:     region,
						Properties: *resource.Properties,
						AccountId:  acctId,
					}

				}
			}(region)
		}
	}
	return out
}

func ParseTypes(types string) <-chan string {
	out := make(chan string)
	defer close(out)
	go func() {
		for _, t := range strings.Split(types, ",") {
			out <- t
		}
	}()
	return out
}

func GetAccountAuthorizationDetailsStage(ctx context.Context, opts []*ntypes.Option, in <-chan string) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)

		config, err := helpers.GetAWSCfg("", ntypes.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)

		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting AWS config: %s", err))
			return
		}

		accountId, err := helpers.GetAccountId(config)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account ID: %s", err))
		}
		fmt.Println(accountId)

		client := iam.NewFromConfig(config)
		output, err := client.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{})
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account authorization details: %s", err))
			return
		}

		res, err := json.Marshal(output)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error marshalling account authorization details: %s", err))
		}

		out <- res
	}()
	return out
}
