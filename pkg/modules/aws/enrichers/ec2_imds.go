package enrichers

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::EC2::Instance", fetchIMDSMetadataWrapper)
}

// EC2DescribeInstancesAPI is the minimal interface needed for testing.
type EC2DescribeInstancesAPI interface {
	DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

func fetchIMDSMetadataWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := ec2.NewFromConfig(cfg.AWSConfig)
	return FetchIMDSMetadata(cfg, r, client)
}

// FetchIMDSMetadata enriches an EC2 instance resource with IMDS metadata properties.
func FetchIMDSMetadata(cfg plugin.EnricherConfig, r *output.AWSResource, client EC2DescribeInstancesAPI) error {
	out, err := client.DescribeInstances(cfg.Context, &ec2.DescribeInstancesInput{
		InstanceIds: []string{r.ResourceID},
	})
	if err != nil {
		// Handle instance not found (terminated and cleaned up)
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidInstanceID.NotFound" {
			return nil
		}
		return fmt.Errorf("failed to describe instance %s: %w", r.ResourceID, err)
	}

	// Extract instance from response
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return nil
	}
	instance := out.Reservations[0].Instances[0]

	// Flatten instance state
	if instance.State != nil {
		r.Properties["InstanceStateName"] = string(instance.State.Name)
	}

	// Add IMDS metadata options (use AWS defaults when nil)
	if instance.MetadataOptions != nil {
		r.Properties["MetadataHttpTokens"] = string(instance.MetadataOptions.HttpTokens)
		r.Properties["MetadataHttpEndpoint"] = string(instance.MetadataOptions.HttpEndpoint)
		if instance.MetadataOptions.HttpPutResponseHopLimit != nil {
			r.Properties["MetadataHttpPutResponseHopLimit"] = int(*instance.MetadataOptions.HttpPutResponseHopLimit)
		}
	} else {
		// AWS defaults: IMDSv1 allowed, endpoint enabled
		r.Properties["MetadataHttpTokens"] = "optional"
		r.Properties["MetadataHttpEndpoint"] = "enabled"
	}

	return nil
}
