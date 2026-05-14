package enrichers

import (
	"context"
	"errors"
	"log/slog"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::Cognito::UserPool", enrichCognitoUserPoolWrapper)
}

// CognitoClient interface for testing
type CognitoClient interface {
	DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error)
	ListUserPoolClients(ctx context.Context, params *cognitoidentityprovider.ListUserPoolClientsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolClientsOutput, error)
	DescribeUserPoolClient(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolClientInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolClientOutput, error)
	ListGroups(ctx context.Context, params *cognitoidentityprovider.ListGroupsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListGroupsOutput, error)
}

func enrichCognitoUserPoolWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := cognitoidentityprovider.NewFromConfig(cfg.AWSConfig)
	return EnrichCognitoUserPool(cfg, r, client)
}

// EnrichCognitoUserPool adds self-signup status, domains, and client configuration to Cognito user pools.
func EnrichCognitoUserPool(cfg plugin.EnricherConfig, r *output.AWSResource, client CognitoClient) error {
	poolID, ok := r.Properties["UserPoolId"].(string)
	if !ok || poolID == "" {
		return nil
	}

	// Describe the user pool
	poolOut, err := client.DescribeUserPool(cfg.Context, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: &poolID,
	})
	if err != nil {
		var notFound *cognitotypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to describe user pool: %w", err)
	}

	pool := poolOut.UserPool

	// Check self-signup
	selfSignupEnabled := pool.AdminCreateUserConfig == nil || !pool.AdminCreateUserConfig.AllowAdminCreateUserOnly
	r.Properties["SelfSignupEnabled"] = selfSignupEnabled

	// Collect domains
	var domains []string
	if pool.Domain != nil && *pool.Domain != "" {
		domains = append(domains, *pool.Domain)
	}
	if pool.CustomDomain != nil && *pool.CustomDomain != "" {
		domains = append(domains, *pool.CustomDomain)
	}
	if len(domains) > 0 {
		r.Properties["Domains"] = domains
	}

	// Collect schema attributes
	if pool.SchemaAttributes != nil {
		var schema []map[string]any
		for _, attr := range pool.SchemaAttributes {
			attrMap := map[string]any{
				"Name":     stringVal(attr.Name),
				"Required": boolVal(attr.Required),
				"Mutable":  boolVal(attr.Mutable),
			}
			schema = append(schema, attrMap)
		}
		r.Properties["Schema"] = schema
	}

	// List and describe user pool clients
	clientsOut, err := client.ListUserPoolClients(cfg.Context, &cognitoidentityprovider.ListUserPoolClientsInput{
		UserPoolId: &poolID,
		MaxResults: int32Ptr(60),
	})
	if err != nil {
		return fmt.Errorf("failed to list user pool clients: %w", err)
	}

	var clientProps []map[string]any
	for _, clientDesc := range clientsOut.UserPoolClients {
		if clientDesc.ClientId == nil {
			continue
		}
		clientOut, err := client.DescribeUserPoolClient(cfg.Context, &cognitoidentityprovider.DescribeUserPoolClientInput{
			UserPoolId: &poolID,
			ClientId:   clientDesc.ClientId,
		})
		if err != nil {
			slog.Warn("failed to describe user pool client",
				"pool_id", poolID,
				"client_id", stringVal(clientDesc.ClientId),
				"error", err,
			)
			continue
		}

		c := clientOut.UserPoolClient
		prop := map[string]any{
			"ClientId":   stringVal(c.ClientId),
			"ClientName": stringVal(c.ClientName),
		}
		if len(c.AllowedOAuthFlows) > 0 {
			var flows []string
			for _, f := range c.AllowedOAuthFlows {
				flows = append(flows, string(f))
			}
			prop["AllowedOAuthFlows"] = flows
		}
		if len(c.CallbackURLs) > 0 {
			prop["CallbackURLs"] = c.CallbackURLs
		}
		if len(c.AllowedOAuthScopes) > 0 {
			prop["AllowedOAuthScopes"] = c.AllowedOAuthScopes
		}
		clientProps = append(clientProps, prop)
	}
	if len(clientProps) > 0 {
		r.Properties["ClientProperties"] = clientProps
	}

	// Collect IAM roles from user pool groups
	groupsOut, err := client.ListGroups(cfg.Context, &cognitoidentityprovider.ListGroupsInput{
		UserPoolId: &poolID,
	})
	if err != nil {
		slog.Warn("failed to list user pool groups",
			"pool_id", poolID,
			"error", err,
		)
	} else if groupsOut != nil {
		var roles []string
		for _, group := range groupsOut.Groups {
			if group.RoleArn != nil && *group.RoleArn != "" {
				roles = append(roles, *group.RoleArn)
			}
		}
		if len(roles) > 0 {
			r.Properties["Roles"] = roles
		}
	}

	return nil
}

func boolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func int32Ptr(i int32) *int32 { return &i }
