package ec2

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSEC2ScreenshotCapture struct {
	*base.NativeAWSLink
}

func NewAWSEC2ScreenshotCapture(args map[string]any) *AWSEC2ScreenshotCapture {
	return &AWSEC2ScreenshotCapture{
		NativeAWSLink: base.NewNativeAWSLink("ec2-screenshot", args),
	}
}

func (a *AWSEC2ScreenshotCapture) Parameters() []plugin.Parameter {
	return base.StandardAWSParams()
}

func (a *AWSEC2ScreenshotCapture) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	if resource.TypeName != "AWS::EC2::Instance" {
		slog.Debug("Skipping non-EC2 instance", "resource_type", resource.TypeName, "resource_id", resource.Identifier)
		return nil, nil
	}

	config, err := a.GetConfig(ctx, resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	ec2Client := ec2.NewFromConfig(config)

	// First check if the instance exists and is in a valid state for screenshots
	instanceState, err := a.getInstanceState(ctx, ec2Client, resource.Identifier)
	if err != nil {
		slog.Error("Failed to get instance state", "instance_id", resource.Identifier, "error", err)
		return nil, nil // Don't fail the chain for missing instances
	}

	if !a.canTakeScreenshot(instanceState) {
		slog.Info("Skipping screenshot for instance in invalid state",
			"instance_id", resource.Identifier,
			"state", instanceState)
		return nil, nil
	}

	// Capture the screenshot
	screenshotInput := &ec2.GetConsoleScreenshotInput{
		InstanceId: &resource.Identifier,
		WakeUp:     aws.Bool(false), // Don't wake hibernated instances
	}

	slog.Info("Capturing console screenshot",
		"instance_id", resource.Identifier,
		"region", resource.Region,
		"account_id", resource.AccountId)

	output, err := ec2Client.GetConsoleScreenshot(ctx, screenshotInput)
	if err != nil {
		// Handle common errors gracefully without failing the chain
		errMsg := err.Error()
		if strings.Contains(errMsg, "InvalidInstanceID") {
			slog.Warn("Instance not found for screenshot capture", "instance_id", resource.Identifier)
			return nil, nil
		}
		if strings.Contains(errMsg, "UnsupportedOperation") {
			slog.Warn("Screenshot not supported for this instance type", "instance_id", resource.Identifier)
			return nil, nil
		}
		if strings.Contains(errMsg, "IncorrectInstanceState") {
			slog.Warn("Instance in incorrect state for screenshot", "instance_id", resource.Identifier)
			return nil, nil
		}

		slog.Error("Failed to capture console screenshot",
			"instance_id", resource.Identifier,
			"profile", a.Profile,
			"error", err)
		return nil, nil // Don't fail the chain
	}

	if output.ImageData == nil || *output.ImageData == "" {
		slog.Warn("No image data returned from screenshot API", "instance_id", resource.Identifier)
		return nil, nil
	}

	// Decode the base64 image data
	imageBytes, err := base64.StdEncoding.DecodeString(*output.ImageData)
	if err != nil {
		slog.Error("Failed to decode base64 image data",
			"instance_id", resource.Identifier,
			"error", err)
		return nil, nil
	}

	// Create ScreenshotData with the captured image
	screenshotData := types.NewScreenshotData(resource, imageBytes)

	slog.Debug("Image format detection",
		"instance_id", resource.Identifier,
		"detected_format", screenshotData.Format,
		"media_type", screenshotData.GetMediaType(),
		"first_4_bytes", fmt.Sprintf("%02X %02X %02X %02X", imageBytes[0], imageBytes[1], imageBytes[2], imageBytes[3]))

	slog.Info("Successfully captured console screenshot",
		"instance_id", resource.Identifier,
		"image_size_bytes", len(imageBytes),
		"captured_at", screenshotData.CapturedAt.Format("2006-01-02 15:04:05"))

	// Return outputs instead of using a.Send()
	return []any{screenshotData}, nil
}

// getInstanceState retrieves the current state of an EC2 instance
func (a *AWSEC2ScreenshotCapture) getInstanceState(ctx context.Context, client *ec2.Client, instanceID string) (string, error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	output, err := client.DescribeInstances(ctx, input)
	if err != nil {
		return "", err
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if *instance.InstanceId == instanceID {
				return string(instance.State.Name), nil
			}
		}
	}

	return "", fmt.Errorf("instance %s not found", instanceID)
}

// canTakeScreenshot determines if an instance is in a valid state for screenshot capture
func (a *AWSEC2ScreenshotCapture) canTakeScreenshot(state string) bool {
	// Screenshots are only possible for running instances
	// Stopped, terminated, or other states will not have console output
	validStates := map[string]bool{
		string(ec2types.InstanceStateNameRunning): true,
	}
	return validStates[state]
}
