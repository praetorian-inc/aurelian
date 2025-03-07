package stages

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
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

func AwsLambdaGetCodeContent(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "LambdaGetCodeContent")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for resource := range in {
			// Skip if not a Lambda function
			if resource.TypeName != "AWS::Lambda::Function" {
				continue
			}

			// Get AWS config
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			// Create Lambda client
			lambdaClient := lambda.NewFromConfig(config)

			// Get function URL to download code
			getFuncInput := &lambda.GetFunctionInput{
				FunctionName: aws.String(resource.Identifier),
			}

			funcOutput, err := lambdaClient.GetFunction(ctx, getFuncInput)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get function %s: %v", resource.Identifier, err))
				continue
			}

			// Get code URL from output
			if funcOutput.Code == nil || funcOutput.Code.Location == nil {
				logger.Error(fmt.Sprintf("No code location found for function %s", resource.Identifier))
				continue
			}

			message.Info(fmt.Sprintf("Downloading code for function %s", resource.Identifier))
			// Download code from URL
			resp, err := http.Get(*funcOutput.Code.Location)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to download code for function %s: %v", resource.Identifier, err))
				continue
			}
			defer resp.Body.Close()

			// Read zip content
			zipBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to read zip content for function %s: %v", resource.Identifier, err))
				continue
			}

			// Open zip archive in memory
			zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to open zip for function %s: %v", resource.Identifier, err))
				continue
			}

			// Process each file in the zip
			for _, file := range zipReader.File {
				// Skip directories
				if file.FileInfo().IsDir() {
					continue
				}

				rc, err := file.Open()
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to open file %s in function %s: %v", file.Name, resource.Identifier, err))
					continue
				}

				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to read file %s in function %s: %v", file.Name, resource.Identifier, err))
					continue
				}

				if len(content) == 0 {
					logger.Debug("Skipping empty file", slog.String("file", file.Name), slog.String("resource", resource.Identifier))
					continue
				}

				// Create NP input for scanning
				out <- types.NpInput{
					ContentBase64: base64.StdEncoding.EncodeToString(content),
					Provenance: types.NpProvenance{
						Platform:     string(modules.AWS),
						ResourceType: "AWS::Lambda::Function::Code",
						ResourceID:   fmt.Sprintf("%s/%s", resource.ToArn().String(), file.Name),
						Region:       resource.Region,
						AccountID:    resource.AccountId,
					},
				}
			}
		}
	}()

	return out
}
