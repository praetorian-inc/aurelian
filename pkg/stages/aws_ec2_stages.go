package stages

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func EC2GetUserDataStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "EC2GetUserDataStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for resource := range in {
			// Skip if not an EC2 instance
			if resource.TypeName != "AWS::EC2::Instance" {
				continue
			}

			// Set up EC2 client
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %v", resource.Region, err))
				continue
			}

			ec2Client := ec2.NewFromConfig(config)

			// Get user data
			input := &ec2.DescribeInstanceAttributeInput{
				Attribute:  ec2types.InstanceAttributeNameUserData,
				InstanceId: aws.String(resource.Identifier),
			}

			output, err := ec2Client.DescribeInstanceAttribute(ctx, input)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get user data for instance %s: %v", resource.Identifier, err))
				continue
			}

			// Skip if no user data
			if output.UserData == nil || output.UserData.Value == nil {
				continue
			}

			// Send decoded user data

			out <- types.NpInput{
				ContentBase64: *output.UserData.Value,
				Provenance: types.NpProvenance{
					Platform:     string(modules.AWS),
					ResourceType: resource.TypeName,
					ResourceID:   resource.Arn.String(),
					Region:       resource.Region,
					AccountID:    resource.AccountId,
				},
			}
		}
	}()

	return out
}
