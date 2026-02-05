package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::ECS::TaskDefinition", ProcessECSTaskDefinition)
}

// ProcessECSTaskDefinition extracts ECS task definition configurations.
// Task definitions often contain environment variables with secrets, image references, and configurations.
func ProcessECSTaskDefinition(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	ecsClient := ecs.NewFromConfig(config)

	// Describe task definition
	input := &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(resource.Identifier),
	}

	output, err := ecsClient.DescribeTaskDefinition(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe task definition %s: %w", resource.Identifier, err)
	}

	if output.TaskDefinition == nil {
		return nil
	}

	// Serialize task definition to JSON for scanning
	// This captures environment variables, secrets, image URIs, and all configuration
	taskDefJSON, err := json.MarshalIndent(output.TaskDefinition, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal task definition: %w", err)
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: string(taskDefJSON),
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Definition", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
