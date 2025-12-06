package ec2

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSEC2UserData struct {
	*base.AwsReconLink
}

func NewAWSEC2UserData(configs ...cfg.Config) chain.Link {
	ec2 := &AWSEC2UserData{}
	ec2.AwsReconLink = base.NewAwsReconLink(ec2, configs...)
	return ec2
}

func (a *AWSEC2UserData) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::EC2::Instance" {
		slog.Info("Skipping non-EC2 instance", "resource", resource)
		return nil
	}

	config, err := a.GetConfigWithRuntimeArgs(resource.Region)
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
		slog.Error("Failed to get user data for instance", "instance", resource.Identifier, "profile", a.Profile, "error", err)
		return nil
	}

	if output.UserData == nil || output.UserData.Value == nil {
		slog.Debug("No user data found for instance", "instance", resource.Identifier)
		return nil
	}

	a.Send(jtypes.NPInput{
		ContentBase64: *output.UserData.Value,
		Provenance: jtypes.NPProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::UserData", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	})

	return nil
}
