package cognito

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// CognitoUserPoolGetDomains is a Janus link that adds domain information to Cognito user pools
type CognitoUserPoolGetDomains struct {
	*chain.Base
}

func NewCognitoUserPoolGetDomains(configs ...cfg.Config) chain.Link {
	l := &CognitoUserPoolGetDomains{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *CognitoUserPoolGetDomains) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("profile", "AWS profile to use").WithDefault("default"),
	}
}

func (l *CognitoUserPoolGetDomains) Process(resource types.EnrichedResourceDescription) error {
	config, err := helpers.GetAWSCfg(resource.Region, l.Arg("profile").(string), nil)
	if err != nil {
		return fmt.Errorf("could not set up client config: %w", err)
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(config)

	cognitoInput := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(resource.Identifier),
	}

	cognitoOutput, err := cognitoClient.DescribeUserPool(l.Context(), cognitoInput)
	if err != nil {
		// Just send the resource along without modification if we can't get domain info
		l.Send(resource)
		return nil
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

	return l.Send(enrichedResource)
}

// CognitoUserPoolDescribeClients is a Janus link that adds client information to Cognito user pools
type CognitoUserPoolDescribeClients struct {
	*chain.Base
}

func NewCognitoUserPoolDescribeClients(configs ...cfg.Config) chain.Link {
	l := &CognitoUserPoolDescribeClients{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *CognitoUserPoolDescribeClients) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("profile", "AWS profile to use").WithDefault("default"),
	}
}

func (l *CognitoUserPoolDescribeClients) Process(resource types.EnrichedResourceDescription) error {
	config, err := helpers.GetAWSCfg(resource.Region, l.Arg("profile").(string), nil)
	if err != nil {
		return fmt.Errorf("could not set up client config: %w", err)
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
		clientsOutput, err := cognitoClient.ListUserPoolClients(l.Context(), cognitoInput)
		if err != nil {
			// If we can't list clients, just pass the resource through with what we have
			break
		}

		for _, client := range clientsOutput.UserPoolClients {
			describeClientInput := &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: aws.String(resource.Identifier),
				ClientId:   client.ClientId,
			}

			describeClientOutput, err := cognitoClient.DescribeUserPoolClient(l.Context(), describeClientInput)
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

	return l.Send(enrichedResource)
}
