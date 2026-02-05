package dispatcher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::SSM::Document", ProcessSSMDocument)
}

// ProcessSSMDocument extracts SSM document content.
// SSM documents can contain embedded scripts, commands, and configuration that may include secrets.
func ProcessSSMDocument(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	ssmClient := ssm.NewFromConfig(config)

	// Get document content
	input := &ssm.GetDocumentInput{
		Name: aws.String(resource.Identifier),
	}

	output, err := ssmClient.GetDocument(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get document %s: %w", resource.Identifier, err)
	}

	if output.Content == nil || len(*output.Content) == 0 {
		// No content found
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: *output.Content,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Content", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
