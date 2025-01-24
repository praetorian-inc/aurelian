package stages

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsLambdaGetFunctionUrl gets the URL of a Lambda function
func AwsLambdaGetFunctionUrl(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "LambdaGetFunctionUrl")
	logger.Info("Getting Lambda function URLs")
	out := make(chan string)
	go func() {
		for resource := range in {
			logger.Debug("Getting URL for Lambda function: " + resource.Identifier)
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
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
					logger.Error(err.Error())
				}
				continue
			}

			out <- *output.FunctionUrl
		}
		close(out)
	}()
	return out
}

// AwsLambdaListFunctions lists Lambda functions
func AwsLambdaListLayers(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListLambdaLayers")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing Lambda Layers")
	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logger.Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)
				lambdaClient := lambda.NewFromConfig(config)
				params := &lambda.ListLayersInput{}
				res, err := lambdaClient.ListLayers(ctx, params)
				if err != nil {
					logger.Error(err.Error())
					return
				}

				for _, resource := range res.Layers {
					latestMatchingVersionStr, err := json.Marshal(resource.LatestMatchingVersion)
					if err != nil {
						logger.Error("Could not marshal Lambda layer version")
						continue
					}
					lastBracketIndex := strings.LastIndex(string(latestMatchingVersionStr), "}")
					newProperties := string(latestMatchingVersionStr)[:lastBracketIndex] + "," + "\"LayerName\":\"" + *resource.LayerName + "\"" + "}"

					out <- types.EnrichedResourceDescription{
						Identifier: *resource.LayerName,
						TypeName:   rtype,
						Region:     region,
						Properties: newProperties,
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

// AwsLambdaListFunctions lists Lambda functions
func AwsLambdaCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "LambdaCheckResourcePolicy")
	logger.Info("Checking Lambda function resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			lambdaClient := lambda.NewFromConfig(config)

			policyInput := &lambda.GetPolicyInput{
				FunctionName: aws.String(resource.Identifier),
			}
			policyOutput, err := lambdaClient.GetPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get Lambda function resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.Policy)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}

// AwsLambdaLayerCheckResourcePolicy checks the resource policy of a Lambda layer
func AwsLambdaLayerCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "LambdaLayerCheckResourcePolicy")
	logger.Info("Checking Lambda layer resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			lambdaClient := lambda.NewFromConfig(config)

			var properties map[string]interface{}
			if err := json.Unmarshal([]byte(resource.Properties.(string)), &properties); err != nil {
				logger.Error("Could not unmarshal Lambda layer version, error: " + err.Error())
				continue
			}
			version, ok := properties["Version"].(float64)
			if !ok {
				logger.Error("Could not find Lambda layer version")
				continue
			}

			policyInput := &lambda.GetLayerVersionPolicyInput{
				LayerName:     aws.String(resource.Identifier),
				VersionNumber: aws.Int64(int64(version)),
			}
			policyOutput, err := lambdaClient.GetLayerVersionPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get Lambda layer resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.Policy)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}
