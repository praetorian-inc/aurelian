package extraction

import (
	"encoding/base64"
	"fmt"

	ec2service "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::EC2::Instance", "ec2-userdata", extractEC2)
}

func extractEC2(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	client := ec2service.NewFromConfig(ctx.AWSConfig)
	instanceID := r.ResourceID
	if id, ok := r.Properties["InstanceId"].(string); ok && id != "" {
		instanceID = id
	}

	resp, err := client.DescribeInstanceAttribute(ctx.Context, &ec2service.DescribeInstanceAttributeInput{InstanceId: &instanceID, Attribute: "userData"})
	if err != nil {
		return fmt.Errorf("DescribeInstanceAttribute failed for %s: %w", instanceID, err)
	}

	missingUserData := resp.UserData == nil || resp.UserData.Value == nil || *resp.UserData.Value == ""
	if missingUserData {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*resp.UserData.Value)
	if err != nil {
		return fmt.Errorf("failed to base64-decode UserData for %s: %w", instanceID, err)
	}

	emptyContent := len(decoded) == 0
	if emptyContent {
		return nil
	}

	out.Send(output.ScanInputFromAWSResource(r, "UserData", decoded))
	return nil
}
