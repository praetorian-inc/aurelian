package secrets

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// EC2UserDataClient is the subset of the EC2 API needed by the EC2 extractor.
type EC2UserDataClient interface {
	DescribeInstanceAttribute(
		ctx context.Context,
		input *ec2.DescribeInstanceAttributeInput,
		opts ...func(*ec2.Options),
	) (*ec2.DescribeInstanceAttributeOutput, error)
}

// extractEC2 fetches UserData from an EC2 instance and emits it as a ScanInput.
func extractEC2(cfg ExtractorConfig, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	awsCfg, err := cfg.AWSConfigFactory(r.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	client := ec2.NewFromConfig(awsCfg)
	return extractEC2WithClient(client, r, out)
}

// extractEC2WithClient is the testable core of the EC2 extractor.
func extractEC2WithClient(client EC2UserDataClient, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	instanceID := r.ResourceID
	// CloudControl sometimes uses InstanceId property
	if id, ok := r.Properties["InstanceId"].(string); ok && id != "" {
		instanceID = id
	}

	resp, err := client.DescribeInstanceAttribute(context.Background(), &ec2.DescribeInstanceAttributeInput{
		InstanceId: &instanceID,
		Attribute:  "userData",
	})
	if err != nil {
		return fmt.Errorf("DescribeInstanceAttribute failed for %s: %w", instanceID, err)
	}

	if resp.UserData == nil || resp.UserData.Value == nil || *resp.UserData.Value == "" {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*resp.UserData.Value)
	if err != nil {
		return fmt.Errorf("failed to base64-decode UserData for %s: %w", instanceID, err)
	}

	if len(decoded) == 0 {
		return nil
	}

	out.Send(ScanInput{
		Content:      decoded,
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Label:        "UserData",
	})

	return nil
}
