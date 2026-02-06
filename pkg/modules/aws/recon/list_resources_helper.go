package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

func listResourcesByType(ctx context.Context, client *cloudcontrol.Client, resourceType, accountID, region string) ([]output.CloudResource, error) {
	var allResources []output.CloudResource
	var nextToken *string

	for {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		results, err := client.ListResources(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources of type %s: %w", resourceType, err)
		}

		for _, desc := range results.ResourceDescriptions {
			var resourceID string
			if desc.Identifier != nil {
				resourceID = *desc.Identifier
			}

			var props map[string]any
			if desc.Properties != nil && *desc.Properties != "" {
				if err := json.Unmarshal([]byte(*desc.Properties), &props); err != nil {
					props = map[string]any{
						"raw_properties": *desc.Properties,
					}
				}
			}

			if resourceID == "subnet-069a1f55fded757a1" {
				fmt.Println("foo")
			}

			resource := output.NewAWSResource(region, resourceType, accountID, resourceID)
			resource.Properties = props
			allResources = append(allResources, resource)
		}

		nextToken = results.NextToken
		if nextToken == nil {
			break
		}
	}

	return allResources, nil
}
