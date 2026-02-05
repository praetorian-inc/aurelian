package ec2

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSEC2UserData struct {
	*base.NativeAWSLink
}

func NewAWSEC2UserData(args map[string]any) *AWSEC2UserData {
	return &AWSEC2UserData{
		NativeAWSLink: base.NewNativeAWSLink("ec2-userdata", args),
	}
}

func (a *AWSEC2UserData) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}
	if resource.TypeName != "AWS::EC2::Instance" {
		slog.Info("Skipping non-EC2 instance", "resource", resource)
		return nil, nil
	}

	config, err := a.GetConfig(ctx, resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil, nil
	}

	ec2Client := ec2.NewFromConfig(config)

	attributeInput := &ec2.DescribeInstanceAttributeInput{
		Attribute:  ec2types.InstanceAttributeNameUserData,
		InstanceId: aws.String(resource.Identifier),
	}

	output, err := ec2Client.DescribeInstanceAttribute(context.TODO(), attributeInput)
	if err != nil {
		slog.Error("Failed to get user data for instance", "instance", resource.Identifier, "profile", a.Profile, "error", err)
		return nil, nil
	}

	if output.UserData == nil || output.UserData.Value == nil {
		slog.Debug("No user data found for instance", "instance", resource.Identifier)
		return nil, nil
	}

	a.Send(types.NpInput{
		ContentBase64: *output.UserData.Value,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::UserData", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	})

	return a.Outputs(), nil
}
