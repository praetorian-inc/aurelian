package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/janus/pkg/util"
)

type AwsEc2UserData struct {
	*AwsReconLink
}

func NewAWSEC2UserData(configs ...cfg.Config) chain.Link {
	ec2 := &AwsEc2UserData{}
	ec2.AwsReconLink = NewAwsReconLink(ec2, configs...)
	return ec2
}

func (a *AwsEc2UserData) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::EC2::Instance" {
		slog.Info("Skipping non-EC2 instance", "resource", resource)
		return nil
	}

	config, err := util.GetAWSConfig(resource.Region, a.profile)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil
	}

	ec2Client := ec2.NewFromConfig(config)

	input := &ec2.DescribeInstanceAttributeInput{
		Attribute:  ec2types.InstanceAttributeNameUserData,
		InstanceId: aws.String(resource.Identifier),
	}

	output, err := ec2Client.DescribeInstanceAttribute(context.TODO(), input)
	if err != nil {
		slog.Error("Failed to get user data for instance", "instance", resource.Identifier, "error", err)
		return nil
	}

	if output.UserData == nil || output.UserData.Value == nil {
		slog.Debug("No user data found for instance", "instance", resource.Identifier)
		return nil
	}

	a.Send(types.NPInput{
		ContentBase64: *output.UserData.Value,
		Provenance: types.NPProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::UserData", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	})

	return nil
}
