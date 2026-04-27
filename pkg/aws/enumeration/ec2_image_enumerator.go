package enumeration

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// EC2ImageEnumerator enumerates EC2 AMIs owned by the account using the
// native EC2 SDK, enriching each image with launch permissions and usage data.
type EC2ImageEnumerator struct {
	plugin.AWSCommonRecon
	provider *AWSConfigProvider
}

// NewEC2ImageEnumerator creates an EC2ImageEnumerator that uses the native EC2 SDK.
func NewEC2ImageEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *EC2ImageEnumerator {
	return &EC2ImageEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

// ResourceType returns the CloudControl type string for EC2 images.
func (l *EC2ImageEnumerator) ResourceType() string {
	return "AWS::EC2::Image"
}

// EnumerateAll enumerates all EC2 AMIs owned by the account across configured regions.
func (l *EC2ImageEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listImagesInRegion(region, accountID, out)
	})
}

// EnumerateByARN fetches a single EC2 AMI by ARN.
func (l *EC2ImageEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}

	imageID, ok := strings.CutPrefix(parsed.Resource, "image/")
	if !ok {
		return fmt.Errorf("invalid EC2 image ARN resource: %q", parsed.Resource)
	}

	if parsed.Region == "" {
		return fmt.Errorf("EC2 image ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create EC2 client for %s: %w", parsed.Region, err)
	}
	client := ec2.NewFromConfig(*cfg)

	result, err := client.DescribeImages(context.Background(), &ec2.DescribeImagesInput{
		ImageIds: []string{imageID},
	})
	if err != nil {
		return fmt.Errorf("describe image %s: %w", imageID, err)
	}
	if len(result.Images) == 0 {
		return fmt.Errorf("image %s not found in %s", imageID, parsed.Region)
	}

	resource, err := buildResource(context.Background(), client, result.Images[0], parsed.AccountID, parsed.Region)
	if err != nil {
		return err
	}
	out.Send(resource)
	return nil
}

func (l *EC2ImageEnumerator) listImagesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create EC2 client for %s: %w", region, err)
	}
	client := ec2.NewFromConfig(*cfg)

	result, err := client.DescribeImages(context.Background(), &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		if handled := handleListError(err, "AWS::EC2::Image", region, nil); handled == nil {
			return nil
		}
		return fmt.Errorf("describe images in %s: %w", region, err)
	}

	if len(result.Images) == 0 {
		slog.Debug("no AMIs found in region", "region", region)
		return nil
	}

	for _, image := range result.Images {
		resource, err := buildResource(context.Background(), client, image, accountID, region)
		if err != nil {
			slog.Warn("failed to build EC2 image resource",
				"image_id", aws.ToString(image.ImageId),
				"region", region,
				"error", err,
			)
			continue
		}
		out.Send(resource)
	}

	return nil
}

func buildResource(ctx context.Context, client *ec2.Client, image ec2types.Image, accountID, region string) (output.AWSResource, error) {
	imageID := aws.ToString(image.ImageId)

	permResult, err := client.DescribeImageAttribute(ctx, &ec2.DescribeImageAttributeInput{
		ImageId:   &imageID,
		Attribute: ec2types.ImageAttributeNameLaunchPermission,
	})
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("describe launch permissions for %s: %w", imageID, err)
	}

	snapshotIDs := extractImageSnapshotIDs(image.BlockDeviceMappings)
	instances := findInstancesUsingImage(ctx, client, imageID)

	return output.AWSResource{
		ResourceType: "AWS::EC2::Image",
		ResourceID:   imageID,
		ARN:          fmt.Sprintf("arn:aws:ec2:%s:%s:image/%s", region, accountID, imageID),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  aws.ToString(image.Name),
		Properties: map[string]any{
			"ImageId":          imageID,
			"Name":             aws.ToString(image.Name),
			"Description":      aws.ToString(image.Description),
			"CreationDate":     aws.ToString(image.CreationDate),
			"Architecture":     string(image.Architecture),
			"IsPublic":         isImagePublic(permResult.LaunchPermissions),
			"SnapshotIds":      snapshotIDs,
			"InUseByInstances": instances,
		},
	}, nil
}

func isImagePublic(permissions []ec2types.LaunchPermission) bool {
	return slices.ContainsFunc(permissions, func(p ec2types.LaunchPermission) bool {
		return p.Group == ec2types.PermissionGroupAll
	})
}

func extractImageSnapshotIDs(mappings []ec2types.BlockDeviceMapping) []string {
	var ids []string
	for _, m := range mappings {
		if m.Ebs != nil && m.Ebs.SnapshotId != nil {
			ids = append(ids, aws.ToString(m.Ebs.SnapshotId))
		}
	}
	return ids
}

func findInstancesUsingImage(ctx context.Context, client *ec2.Client, imageID string) []string {
	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("image-id"),
				Values: []string{imageID},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err != nil {
		slog.Debug("failed to find instances using image",
			"image_id", imageID,
			"error", err,
		)
		return nil
	}

	var instanceIDs []string
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			instanceIDs = append(instanceIDs, aws.ToString(instance.InstanceId))
		}
	}
	return instanceIDs
}
