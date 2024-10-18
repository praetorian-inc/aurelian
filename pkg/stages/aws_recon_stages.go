package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func Ec2ListPublic(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for region := range in {
				logs.ConsoleLogger().Debug("Listing public EC2 resources for " + region)
				config, _ := helpers.GetAWSCfg(region, types.GetOptionByName("profile", opts).Value)
				client := ec2.NewFromConfig(config)

				ec2Input := ec2.DescribeInstancesInput{
					Filters: []ec2types.Filter{
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

func LambdaGetFunctionUrl(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logs.ConsoleLogger().Info("Getting Lambda function URLs")
	out := make(chan string)
	go func() {
		for resource := range in {
			logs.ConsoleLogger().Debug("Getting URL for Lambda function: " + resource.Identifier)
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				out <- ""
			}
			client := lambda.NewFromConfig(config)
			params := &lambda.GetFunctionUrlConfigInput{
				FunctionName: aws.String(resource.Identifier),
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
		close(out)
	}()
	return out
}

func ListLambdaFunctions(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
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

func GetRegions(ctx context.Context, opts []*types.Option) <-chan string {
	regChan := make(chan string)
	go func() {
		defer close(regChan)
		enabled, _ := helpers.EnabledRegions(types.GetOptionByName("profile", opts).Value)

		for _, region := range enabled {
			regChan <- region
		}
	}()

	return regChan
}

func CloudControlListResources(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing resources")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
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
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
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
					out <- types.EnrichedResourceDescription{
						Identifier: *resource.Identifier,
						TypeName:   rtype,
						Region:     region,
						Properties: *resource.Properties,
						AccountId:  acctId,
					}
				}
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func CloudControlGetResource(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan *cloudcontrol.GetResourceOutput {
	out := make(chan *cloudcontrol.GetResourceOutput)

	for resource := range in {
		cfg, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
		if err != nil {
			panic(err)
		}

		cc := cloudcontrol.NewFromConfig(cfg)

		params := &cloudcontrol.GetResourceInput{
			Identifier: &resource.Identifier,
			TypeName:   &resource.TypeName,
		}
		go func(resource types.EnrichedResourceDescription) {
			defer close(out)
			retries := 3
			backoff := 1000

			for i := 0; i < retries; i++ {
				res, err := cc.GetResource(ctx, params)
				if err != nil && strings.Contains(err.Error(), "ThrottlingException") {
					logs.ConsoleLogger().Info("ThrottlingException encountered. Retrying in " + strconv.Itoa(backoff) + "ms")
					b := time.Duration(backoff) * time.Millisecond * time.Duration(i)
					time.Sleep(b)
					continue
				}

				if err != nil {
					logs.ConsoleLogger().Error(fmt.Sprintf("Error getting resource: %s, %s", resource.Identifier, err))
					break
				}

				out <- res
				return
			}
		}(resource)
	}

	return out
}

func ParseTypes(types string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for _, t := range strings.Split(types, ",") {
			out <- t
		}
	}()
	return out
}

func GetAccountAuthorizationDetailsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)

		config, err := helpers.GetAWSCfg("", types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)

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

func AwsPublicResources(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {

	out := make(chan string)
	//var pipelines []stages.Stage[string, string]

	go func() {
		defer close(out)
		for rtype := range in {

			logs.ConsoleLogger().Debug("Running recon for resource type: " + rtype)
			var pl Stage[string, string]
			var err error
			switch rtype {
			case "AWS::Lambda::Function":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					LambdaGetFunctionUrl,
				)

			case "AWS::EC2::Instance":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ToJson[types.EnrichedResourceDescription],
					// TODO - add jq filter to get public ip and public dns name
					JqFilter(".Properties | fromjson | select(.PublicIp != null) | .PublicIp"),
					ToString[[]byte],
				)

			case "AWS::S3::Bucket":
				fmt.Println("S3 bucket ")
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					// Echo[types.EnrichedResourceDescription],
					CloudControlGetResource,
					Echo[*cloudcontrol.GetResourceOutput],
					ToJson[*cloudcontrol.GetResourceOutput],
					JqFilter(".ResourceDescription.Properties | fromjson | select(.RegionalDomainName != null) | .RegionalDomainName"),
					ToString[[]byte],
				)

			default:
				continue
			}

			if err != nil {
				logs.ConsoleLogger().Error("Failed to " + rtype + " create pipeline: " + err.Error())
				continue
			}

			wg := new(sync.WaitGroup)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range pl(ctx, opts, Generator([]string{rtype})) {
					out <- s
				}
			}()
			wg.Wait()
		}

		//stages.FanStages(ctx, opts, in, out, pipelines...)
	}()

	return out

}

func ToJson[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		for resource := range in {
			res, err := json.Marshal(resource)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				continue
			}
			out <- res
		}
	}()
	return out
}
