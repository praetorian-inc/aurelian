package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func listResources(ctx context.Context, awsCfg aws.Config, resourceType, accountID, region string) ([]output.CloudResource, error) {
	client := cloudcontrol.NewFromConfig(awsCfg)
	return listResourcesByType(ctx, client, resourceType, accountID, region)
}

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
			erd := resourceDescriptionToERD(desc, resourceType, accountID, region)
			resource := erd.ToCloudResource()
			allResources = append(allResources, resource)
		}

		nextToken = results.NextToken
		if nextToken == nil {
			break
		}
	}

	return allResources, nil
}

func resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) *types.EnrichedResourceDescription {
	var erdRegion string
	if helpers.IsGlobalService(rType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	erd := types.NewEnrichedResourceDescription(
		*resource.Identifier,
		rType,
		erdRegion,
		accountId,
		*resource.Properties,
	)

	return &erd
}
