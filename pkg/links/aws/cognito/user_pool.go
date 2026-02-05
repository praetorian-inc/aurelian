package cognito

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// CognitoUserPoolGetDomains adds domain information to Cognito user pools
type CognitoUserPoolGetDomains struct {
	*base.NativeAWSLink
}

func NewCognitoUserPoolGetDomains(args map[string]any) *CognitoUserPoolGetDomains {
	return &CognitoUserPoolGetDomains{
		NativeAWSLink: base.NewNativeAWSLink("cognito-user-pool-get-domains", args),
	}
}

func (l *CognitoUserPoolGetDomains) Parameters() []plugin.Parameter {
	return base.StandardAWSParams()
}

func (l *CognitoUserPoolGetDomains) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected types.EnrichedResourceDescription, got %T", input)
	}

	config, err := helpers.GetAWSCfg(resource.Region, l.Profile, nil, "none")
	if err != nil {
		return nil, fmt.Errorf("could not set up client config: %w", err)
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(config)

	cognitoInput := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(resource.Identifier),
	}

	cognitoOutput, err := cognitoClient.DescribeUserPool(ctx, cognitoInput)
	if err != nil {
		// Just send the resource along without modification if we can't get domain info
		l.Send(resource)
		return l.Outputs(), nil
	}

	// Convert the properties to a map to make it easier to work with
	var propsMap map[string]interface{}
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			propsMap = make(map[string]interface{})
		}
	case map[string]interface{}:
		propsMap = props
	default:
		propsMap = make(map[string]interface{})
	}

	// Add self-signup information
	isSelfSignupEnabled := !cognitoOutput.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly
	propsMap["SelfSignupEnabled"] = isSelfSignupEnabled

	// Collect domains and sign-up URLs
	var domains []string
	var signupUrls []string

	if domain := cognitoOutput.UserPool.Domain; domain != nil {
		formattedDomain := fmt.Sprintf("https://%s.auth.%s.amazoncognito.com", *domain, resource.Region)
		domains = append(domains, formattedDomain)

		// Add signup URL if self-registration is enabled
		if isSelfSignupEnabled {
			signupUrl := fmt.Sprintf("%s/signup", formattedDomain)
			signupUrls = append(signupUrls, signupUrl)
		}
	}

	if customDomain := cognitoOutput.UserPool.CustomDomain; customDomain != nil {
		formattedCustomDomain := fmt.Sprintf("https://%s", *customDomain)
		domains = append(domains, formattedCustomDomain)

		// Add signup URL if self-registration is enabled
		if isSelfSignupEnabled {
			signupUrl := fmt.Sprintf("%s/signup", formattedCustomDomain)
			signupUrls = append(signupUrls, signupUrl)
		}
	}

	// Only add domains if we found any
	if len(domains) > 0 {
		propsMap["Domains"] = domains
	}

	// Add signup URLs if self-registration is enabled and domains are available
	if isSelfSignupEnabled && len(signupUrls) > 0 {
		propsMap["SignupUrls"] = signupUrls
	}

	// Create a new resource with the updated properties
	enrichedResource := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: propsMap,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	l.Send(enrichedResource)
	return l.Outputs(), nil
}

// CognitoUserPoolDescribeClients adds client information to Cognito user pools
type CognitoUserPoolDescribeClients struct {
	*base.NativeAWSLink
}

func NewCognitoUserPoolDescribeClients(args map[string]any) *CognitoUserPoolDescribeClients {
	return &CognitoUserPoolDescribeClients{
		NativeAWSLink: base.NewNativeAWSLink("cognito-user-pool-describe-clients", args),
	}
}

func (l *CognitoUserPoolDescribeClients) Parameters() []plugin.Parameter {
	return base.StandardAWSParams()
}

func (l *CognitoUserPoolDescribeClients) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected types.EnrichedResourceDescription, got %T", input)
	}

	config, err := helpers.GetAWSCfg(resource.Region, l.Profile, nil, "none")
	if err != nil {
		return nil, fmt.Errorf("could not set up client config: %w", err)
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(config)

	// Convert the properties to a map if it's not already one
	var propsMap map[string]interface{}
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			propsMap = make(map[string]interface{})
		}
	case map[string]interface{}:
		propsMap = props
	default:
		propsMap = make(map[string]interface{})
	}

	cognitoInput := &cognitoidentityprovider.ListUserPoolClientsInput{
		UserPoolId: aws.String(resource.Identifier),
	}

	var clientProperties []map[string]interface{}

	for {
		clientsOutput, err := cognitoClient.ListUserPoolClients(ctx, cognitoInput)
		if err != nil {
			// If we can't list clients, just pass the resource through with what we have
			break
		}

		for _, client := range clientsOutput.UserPoolClients {
			describeClientInput := &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: aws.String(resource.Identifier),
				ClientId:   client.ClientId,
			}

			describeClientOutput, err := cognitoClient.DescribeUserPoolClient(ctx, describeClientInput)
			if err != nil {
				continue
			}

			clientProperty := map[string]interface{}{
				"ClientId":           describeClientOutput.UserPoolClient.ClientId,
				"ClientName":         describeClientOutput.UserPoolClient.ClientName,
				"CallbackURLs":       describeClientOutput.UserPoolClient.CallbackURLs,
				"LogoutURLs":         describeClientOutput.UserPoolClient.LogoutURLs,
				"AllowedOAuthFlows":  describeClientOutput.UserPoolClient.AllowedOAuthFlows,
				"AllowedOAuthScopes": describeClientOutput.UserPoolClient.AllowedOAuthScopes,
				"ExplicitAuthFlows":  describeClientOutput.UserPoolClient.ExplicitAuthFlows,
				"DefaultRedirectURI": describeClientOutput.UserPoolClient.DefaultRedirectURI,
			}

			clientProperties = append(clientProperties, clientProperty)
		}

		if clientsOutput.NextToken == nil {
			break
		}

		cognitoInput.NextToken = clientsOutput.NextToken
	}

	// Add clients to the properties map
	if len(clientProperties) > 0 {
		propsMap["ClientProperties"] = clientProperties
	} else {
		propsMap["ClientProperties"] = nil
	}

	// Create a new resource with the updated properties
	enrichedResource := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: propsMap,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	l.Send(enrichedResource)
	return l.Outputs(), nil
}
