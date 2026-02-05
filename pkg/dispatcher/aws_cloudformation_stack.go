package dispatcher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::CloudFormation::Stack", ProcessCloudFormationStack)
}

// ProcessCloudFormationStack extracts CloudFormation stack templates and parameters.
// Stack templates and parameters often contain secrets like API keys, credentials, or configuration.
func ProcessCloudFormationStack(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	cfnClient := cloudformation.NewFromConfig(config)

	// Get stack details including template and parameters
	input := &cloudformation.GetTemplateInput{
		StackName: aws.String(resource.Identifier),
	}

	output, err := cfnClient.GetTemplate(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get template for stack %s: %w", resource.Identifier, err)
	}

	if output.TemplateBody == nil || len(*output.TemplateBody) == 0 {
		// No template found - this is normal for some stacks
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: *output.TemplateBody,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Template", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
