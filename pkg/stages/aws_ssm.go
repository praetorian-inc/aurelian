package stages

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsSsmListDocuments lists user-defined SSM documents in an account
// AwsSsmListDocuments lists only user-defined SSM documents
func AwsSsmListDocuments(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SSMListDocuments")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing SSM documents")
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

	go func() {
		defer close(out)
		for rtype := range rtype {
			// Skip if not SSM document type
			if rtype != "AWS::SSM::Document" {
				continue
			}

			for _, region := range regions {
				logger.Debug("Listing SSM documents in region: " + region)
				wg.Add(1)
				go func(region string) {
					defer wg.Done()
					config, _ := helpers.GetAWSCfg(region, profile, opts)
					ssmClient := ssm.NewFromConfig(config)

					var nextToken *string
					for {
						input := &ssm.ListDocumentsInput{
							Filters: []ssmtypes.DocumentKeyValuesFilter{
								{
									Key:    aws.String("Owner"),
									Values: []string{"Self"},
								},
							},
							NextToken: nextToken,
						}

						result, err := ssmClient.ListDocuments(ctx, input)
						if err != nil {
							logger.Error("Failed to list SSM documents: " + err.Error())
							break
						}

						for _, doc := range result.DocumentIdentifiers {
							logger.Debug("Processing document: " + *doc.Name)

							// Get full document content
							docInput := &ssm.GetDocumentInput{
								Name: doc.Name,
							}
							docOutput, err := ssmClient.GetDocument(ctx, docInput)
							if err != nil {
								logger.Error("Failed to get document " + *doc.Name + ": " + err.Error())
								continue
							}

							properties, err := json.Marshal(map[string]interface{}{
								"Name":            doc.Name,
								"DocumentType":    doc.DocumentType,
								"DocumentVersion": doc.DocumentVersion,
								"Content":         docOutput.Content,
							})
							if err != nil {
								logger.Error("Failed to marshal document properties: " + err.Error())
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *doc.Name,
								TypeName:   rtype,
								Region:     region,
								Properties: string(properties),
								AccountId:  acctId,
							}
						}

						nextToken = result.NextToken
						if nextToken == nil {
							break
						}
					}
				}(region)
			}
		}
		wg.Wait()
	}()

	return out
}

// AwsSsmListParameters lists SSM parameters in an account
func AwsSsmListParameters(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SSMListParameters")
	out := make(chan types.EnrichedResourceDescription)

	go func() {
		defer close(out)
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}

			ssmClient := ssm.NewFromConfig(config)
			input := &ssm.DescribeParametersInput{}

			for {
				result, err := ssmClient.DescribeParameters(ctx, input)
				if err != nil {
					logger.Error("Failed to list SSM parameters: " + err.Error())
					break
				}

				for _, param := range result.Parameters {
					// Get parameter value
					paramInput := &ssm.GetParameterInput{
						Name:           param.Name,
						WithDecryption: aws.Bool(true),
					}
					paramOutput, err := ssmClient.GetParameter(ctx, paramInput)
					if err != nil {
						logger.Error("Failed to get parameter " + *param.Name + ": " + err.Error())
						continue
					}

					properties, err := json.Marshal(map[string]interface{}{
						"Name":             param.Name,
						"Type":             param.Type,
						"Value":            paramOutput.Parameter.Value,
						"Description":      param.Description,
						"LastModifiedDate": param.LastModifiedDate,
						"Version":          param.Version,
					})
					if err != nil {
						logger.Error("Failed to marshal parameter properties: " + err.Error())
						continue
					}

					out <- types.EnrichedResourceDescription{
						Identifier: *param.Name,
						TypeName:   resource.TypeName,
						Region:     resource.Region,
						Properties: string(properties),
						AccountId:  resource.AccountId,
					}
				}

				if result.NextToken == nil {
					break
				}
				input.NextToken = result.NextToken
			}
		}
	}()

	return out
}
