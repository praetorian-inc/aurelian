package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsCognitoUserPoolGetDomains gets the domains for a Cognito user pool.
func AwsCognitoUserPoolGetDomains(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CognitoUserPoolGetDomains")
	logger.Info("Checking Cognito user pool domains")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			cognitoClient := cognitoidentityprovider.NewFromConfig(config)

			cognitoInput := &cognitoidentityprovider.DescribeUserPoolInput{
				UserPoolId: aws.String(resource.Identifier),
			}
			cognitoOutput, err := cognitoClient.DescribeUserPool(ctx, cognitoInput)
			if err != nil {
				logger.Debug("Could not describe " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				if cognitoOutput.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly {
					out <- resource
					continue
				}

				domainString := "\"Domains\":["

				domain := cognitoOutput.UserPool.Domain
				var formattedDomain string
				if domain != nil {
					formattedDomain = fmt.Sprintf("https://%s.auth.%s.amazoncognito.com", *domain, resource.Region)
					domainString = domainString + "\"" + formattedDomain + "\","
				}

				customDomain := cognitoOutput.UserPool.CustomDomain
				var formattedCustomDomain string
				if customDomain != nil {
					formattedCustomDomain = fmt.Sprintf("https://%s", *customDomain)
					domainString = domainString + "\"" + formattedCustomDomain + "\","
				}

				if domain == nil && customDomain == nil {
					out <- resource
					continue
				}

				domainString = strings.TrimSuffix(domainString, ",")
				domainString = domainString + "]"

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + domainString + "}"

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

// AwsCognitoUserPoolDescribeClients gets the clients for a Cognito user pool.
func AwsCognitoUserPoolDescribeClients(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CognitoUserPoolDescribeClients")
	logger.Info("Checking Cognito user pool clients")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			cognitoClient := cognitoidentityprovider.NewFromConfig(config)

			cognitoInput := &cognitoidentityprovider.ListUserPoolClientsInput{
				UserPoolId: aws.String(resource.Identifier),
			}

			clientPropertiesString := "\"ClientProperties\":["
			for {
				clientsOutput, err := cognitoClient.ListUserPoolClients(ctx, cognitoInput)
				if err != nil {
					logger.Info("Could not list user pool clients for " + resource.Identifier + ", error: " + err.Error())
					out <- resource
					break
				}
				for _, client := range clientsOutput.UserPoolClients {
					describeClientInput := &cognitoidentityprovider.DescribeUserPoolClientInput{
						UserPoolId: aws.String(resource.Identifier),
						ClientId:   client.ClientId,
					}
					describeClientOutput, err := cognitoClient.DescribeUserPoolClient(ctx, describeClientInput)
					if err != nil {
						logger.Info("Could not describe user pool client " + *client.ClientId + " for " + resource.Identifier + ", error: " + err.Error())
						continue
					}

					clientProperties := map[string]interface{}{
						"CallbackURLs":       describeClientOutput.UserPoolClient.CallbackURLs,
						"ClientId":           describeClientOutput.UserPoolClient.ClientId,
						"AllowedOAuthFlows":  describeClientOutput.UserPoolClient.AllowedOAuthFlows,
						"AllowedOAuthScopes": describeClientOutput.UserPoolClient.AllowedOAuthScopes,
					}

					clientPropertiesBytes, err := json.Marshal(clientProperties)
					if err != nil {
						logger.Info("Could not marshal user pool client properties for " + *client.ClientId + ", error: " + err.Error())
						continue
					}
					clientPropertiesString = clientPropertiesString + string(clientPropertiesBytes) + ","
				}

				if clientsOutput.NextToken == nil {
					break
				}
				cognitoInput.NextToken = clientsOutput.NextToken
			}

			if clientPropertiesString == "\"ClientProperties\":[" {
				clientPropertiesString = "\"ClientProperties\":null"
			} else {
				clientPropertiesString = strings.TrimSuffix(clientPropertiesString, ",")
				clientPropertiesString = clientPropertiesString + "]"
			}
			lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
			newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + clientPropertiesString + "}"
			logger.Info(newProperties)

			out <- types.EnrichedResourceDescription{
				Identifier: resource.Identifier,
				TypeName:   resource.TypeName,
				Region:     resource.Region,
				Properties: newProperties,
				AccountId:  resource.AccountId,
			}
		}
		close(out)
	}()
	return out
}
