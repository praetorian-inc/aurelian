package dispatcher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::StepFunctions::StateMachine", ProcessStepFunctions)
}

// ProcessStepFunctions extracts Step Functions state machine definitions.
// State machine definitions may contain embedded credentials, API endpoints, or configuration.
func ProcessStepFunctions(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	sfnClient := sfn.NewFromConfig(config)

	// Describe state machine to get definition
	input := &sfn.DescribeStateMachineInput{
		StateMachineArn: aws.String(resource.Arn.String()),
	}

	output, err := sfnClient.DescribeStateMachine(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe state machine %s: %w", resource.Identifier, err)
	}

	if output.Definition == nil || len(*output.Definition) == 0 {
		// No definition found
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: *output.Definition,
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
