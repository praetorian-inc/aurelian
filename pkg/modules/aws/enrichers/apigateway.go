package enrichers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::ApiGateway::RestApi", enrichAPIGatewayWrapper)
}

// APIGatewayClient is the subset of the apigateway API used for enrichment.
type APIGatewayClient interface {
	GetResources(ctx context.Context, params *apigateway.GetResourcesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error)
}

func enrichAPIGatewayWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := apigateway.NewFromConfig(cfg.AWSConfig)
	return EnrichAPIGatewayRestAPI(cfg, r, client)
}

// EnrichAPIGatewayRestAPI counts methods on a REST API whose AuthorizationType
// is NONE without an API key (unauthenticated). Methods are sub-resources not
// returned by CloudControl; GetResources with the "methods" embed returns them
// with their authorization settings, avoiding a GetMethod call per method.
func EnrichAPIGatewayRestAPI(cfg plugin.EnricherConfig, r *output.AWSResource, client APIGatewayClient) error {
	apiID, _ := r.Properties["RestApiId"].(string)
	if apiID == "" {
		// RestApiId is the CloudControl primary identifier, so ResourceID holds
		// it when the sparse list payload omits the property.
		apiID = r.ResourceID
	}
	if apiID == "" {
		return nil
	}

	var total, unauthenticated int
	var position *string
	for {
		out, err := client.GetResources(cfg.Context, &apigateway.GetResourcesInput{
			RestApiId: &apiID,
			Embed:     []string{"methods"},
			Position:  position,
		})
		if err != nil {
			return fmt.Errorf("failed to get resources for api %s: %w", apiID, err)
		}
		for _, resource := range out.Items {
			for _, method := range resource.ResourceMethods {
				total++
				authType := ""
				if method.AuthorizationType != nil {
					authType = *method.AuthorizationType
				}
				apiKeyRequired := method.ApiKeyRequired != nil && *method.ApiKeyRequired
				if authType == "NONE" && !apiKeyRequired {
					unauthenticated++
				}
			}
		}
		if out.Position == nil {
			break
		}
		position = out.Position
	}

	r.Properties["TotalMethodCount"] = total
	r.Properties["UnauthenticatedMethodCount"] = unauthenticated
	return nil
}
