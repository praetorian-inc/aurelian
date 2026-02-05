package dispatcher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::ECR::Repository", ProcessECRRepository)
}

// ProcessECRRepository extracts ECR repository policies and configurations.
// Repository policies may contain secrets or access credentials.
func ProcessECRRepository(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	ecrClient := ecr.NewFromConfig(config)

	// Get repository policy
	policyInput := &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(resource.Identifier),
	}

	policyOutput, err := ecrClient.GetRepositoryPolicy(ctx, policyInput)
	if err != nil {
		// Repository may not have a policy - this is normal
		return nil
	}

	if policyOutput.PolicyText == nil || len(*policyOutput.PolicyText) == 0 {
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: *policyOutput.PolicyText,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Policy", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
