package dispatcher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::EC2::Instance", ProcessEC2Instance)
}

// ProcessEC2Instance extracts UserData from EC2 instances.
// UserData often contains secrets like API keys, passwords, or configuration.
func ProcessEC2Instance(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	ec2Client := ec2.NewFromConfig(config)

	input := &ec2.DescribeInstanceAttributeInput{
		Attribute:  ec2types.InstanceAttributeNameUserData,
		InstanceId: aws.String(resource.Identifier),
	}

	output, err := ec2Client.DescribeInstanceAttribute(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get user data for instance %s: %w", resource.Identifier, err)
	}

	if output.UserData == nil || output.UserData.Value == nil {
		// No user data found - this is normal, not an error
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		ContentBase64: *output.UserData.Value,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::UserData", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
