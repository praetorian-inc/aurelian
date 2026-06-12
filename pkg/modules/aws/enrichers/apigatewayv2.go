package enrichers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apiv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::ApiGatewayV2::Api", enrichAPIGatewayV2Wrapper)
}

// APIGatewayV2Client is the subset of the apigatewayv2 API used for enrichment.
type APIGatewayV2Client interface {
	GetRoutes(ctx context.Context, params *apigatewayv2.GetRoutesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
}

func enrichAPIGatewayV2Wrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := apigatewayv2.NewFromConfig(cfg.AWSConfig)
	return EnrichAPIGatewayV2(cfg, r, client)
}

// EnrichAPIGatewayV2 counts routes on an HTTP/WebSocket API whose
// AuthorizationType is NONE (unauthenticated). Routes are independent
// sub-resources not returned by CloudControl, so they must be fetched.
func EnrichAPIGatewayV2(cfg plugin.EnricherConfig, r *output.AWSResource, client APIGatewayV2Client) error {
	apiID, _ := r.Properties["ApiId"].(string)
	if apiID == "" {
		// ApiId is the CloudControl primary identifier, so ResourceID holds it
		// when the sparse list payload omits the property.
		apiID = r.ResourceID
	}
	if apiID == "" {
		return nil
	}

	var total, unauthenticated int
	var nextToken *string
	for {
		out, err := client.GetRoutes(cfg.Context, &apigatewayv2.GetRoutesInput{
			ApiId:     &apiID,
			NextToken: nextToken,
		})
		if err != nil {
			return fmt.Errorf("failed to get routes for api %s: %w", apiID, err)
		}
		for _, route := range out.Items {
			total++
			if route.AuthorizationType == apiv2types.AuthorizationTypeNone {
				unauthenticated++
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	r.Properties["TotalRouteCount"] = total
	r.Properties["UnauthenticatedRouteCount"] = unauthenticated
	return nil
}
