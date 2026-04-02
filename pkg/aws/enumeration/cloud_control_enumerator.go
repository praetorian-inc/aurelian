package enumeration

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"log/slog"
	"strings"
)

type CloudControlEnumerator struct {
	plugin.AWSCommonRecon
	CrossRegionActor *ratelimit.CrossRegionActor
	provider         *AWSConfigProvider
}

func NewCloudControlEnumerator(options plugin.AWSCommonRecon) *CloudControlEnumerator {
	return NewCloudControlEnumeratorWithProvider(options, NewAWSConfigProvider(options))
}

func NewCloudControlEnumeratorWithProvider(options plugin.AWSCommonRecon, provider *AWSConfigProvider) *CloudControlEnumerator {
	return &CloudControlEnumerator{
		AWSCommonRecon:   options,
		CrossRegionActor: ratelimit.NewCrossRegionActor(options.Concurrency),
		provider:         provider,
	}
}

func (cc *CloudControlEnumerator) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	_, err := awsaarn.Parse(identifier)
	if err == nil {
		return cc.EnumerateByARN(identifier, out)
	}

	isResourceType := strings.HasPrefix(identifier, "AWS::")
	if isResourceType {
		return cc.EnumerateByType(identifier, out)
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

func (cc *CloudControlEnumerator) EnumerateByARN(resourceARN string, out *pipeline.P[output.AWSResource]) error {
	resource, err := cc.getResourceByARN(resourceARN)
	if cc.isSkippableError(err) {
		slog.Debug("skipping arn", "arn", resourceARN, "error", err)
		return nil
	}
	if err != nil {
		return err
	}

	out.Send(resource)
	return nil
}

func (cc *CloudControlEnumerator) getResourceByARN(arn string) (output.AWSResource, error) {
	region, resourceType, identifier, err := cc.resolveARNTarget(arn)
	if err != nil {
		return output.AWSResource{}, err
	}

	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.provider.GetAccountID(region)
	if err != nil {
		return output.AWSResource{}, err
	}

	result, err := client.GetResource(context.Background(), &cloudcontrol.GetResourceInput{
		TypeName:   aws.String(resourceType),
		Identifier: aws.String(identifier),
	})
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("get %s %s: %w", resourceType, identifier, err)
	}

	cr := awshelpers.CloudControlToAWSResource(*result.ResourceDescription, resourceType, accountID, region)
	return cr, nil
}

func (cc *CloudControlEnumerator) resolveARNTarget(resourceARN string) (string, string, string, error) {
	parsed, err := awsaarn.Parse(resourceARN)
	if err != nil {
		return "", "", "", fmt.Errorf("parse arn %q: %w", resourceARN, err)
	}

	resourceType, ok := types.ResolveResourceType(parsed.Service, parsed.Resource)
	if !ok {
		return "", "", "", fmt.Errorf("unsupported arn service %q", parsed.Service)
	}

	region, err := cc.resolveResourceRegion(parsed, resourceType)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve region for %q: %w", resourceARN, err)
	}

	identifier := parsed.Resource
	if newID, ok := cc.requiresSpecialIdentifier(resourceType, resourceARN, identifier); ok {
		identifier = newID
	}

	return region, resourceType, identifier, nil
}

// resolveResourceRegion determines the region for a parsed ARN. It handles
// global services, S3 (which omits region from its ARN), and standard ARNs.
func (cc *CloudControlEnumerator) resolveResourceRegion(parsed awsaarn.ARN, resourceType string) (string, error) {
	region := parsed.Region
	if awshelpers.IsGlobalService(resourceType) {
		region = "us-east-1"
	}

	if region == "" && parsed.Service == "s3" {
		resolved, err := cc.resolveS3BucketRegion(parsed.Resource)
		if err != nil {
			return "", fmt.Errorf("resolve s3 bucket region: %w", err)
		}
		region = resolved
	}

	if region == "" {
		return "", fmt.Errorf("region not found for arn %q", parsed.String())
	}

	return region, nil
}

// resolveS3BucketRegion uses the S3 GetBucketLocation API to determine the
// region of a bucket, since S3 ARNs do not contain a region component.
func (cc *CloudControlEnumerator) resolveS3BucketRegion(bucketName string) (string, error) {
	// GetBucketLocation can be called from any region.
	awsCfg, err := cc.provider.GetAWSConfig("us-east-1")
	if err != nil {
		return "", err
	}

	client := s3.NewFromConfig(*awsCfg)
	locOut, err := client.GetBucketLocation(context.Background(), &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return "", fmt.Errorf("get bucket location: %w", err)
	}

	region := string(locOut.LocationConstraint)
	if region == "" {
		region = "us-east-1"
	}
	return region, nil
}

func (cc *CloudControlEnumerator) requiresSpecialIdentifier(resourceType, resourceARN, resourceID string) (string, bool) {
	parsers := map[string]func(string, string) string{
		"AWS::SNS::Topic":                  cc.parseAsARN,
		"AWS::EC2::Instance":               cc.parseEC2InstanceID,
		"AWS::CloudFormation::Stack":       cc.parseCloudFormationStackID,
		"AWS::StepFunctions::StateMachine": cc.parseAsARN,
		"AWS::ECS::TaskDefinition":         cc.parseTaskDefinition,
	}

	parser, ok := parsers[resourceType]
	if !ok {
		return "", false
	}

	return parser(resourceARN, resourceID), ok
}

func (cc *CloudControlEnumerator) parseAsARN(resourceARN, _ string) string {
	return resourceARN
}

func (cc *CloudControlEnumerator) parseEC2InstanceID(_, instanceID string) string {
	// example: instance/i-123456789012
	parts := strings.Split(instanceID, "/")
	if len(parts) != 2 {
		return instanceID
	}

	return parts[1]
}

func (cc *CloudControlEnumerator) parseCloudFormationStackID(_, stackID string) string {
	// example: stack/StackSet-Chariot-Deployment-a00b9d08-b877-4781-a772-c3f798f5eeac/f6eecfa0-837a-11f0-aa31-0affe997852d
	parts := strings.Split(stackID, "/")
	if len(parts) < 2 {
		return stackID
	}

	return parts[1]
}

func (cc *CloudControlEnumerator) parseTaskDefinition(_, taskDefinition string) string {
	// example: task-definition/aurelian-sec-c22f7fe9-secret-task:1
	parts := strings.Split(taskDefinition, "/")
	if len(parts) < 2 {
		return taskDefinition
	}
	return parts[1]
}

// EnumerateByType enumerates a single resource type across all regions, emitting each
// resource into out as pages are fetched. Its signature matches the fn
// parameter of pipeline.Pipe[string, output.AWSResource].
func (cc *CloudControlEnumerator) EnumerateByType(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if len(cc.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	actor := ratelimit.NewCrossRegionActor(cc.Concurrency)
	return actor.ActInRegions(cc.Regions, func(region string) error {
		return cc.listInRegionByType(region, resourceType, out)
	})
}

func (cc *CloudControlEnumerator) listInRegionByType(region, resourceType string, out *pipeline.P[output.AWSResource]) error {
	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.provider.GetAccountID(region)
	if err != nil {
		return err
	}

	err = cc.listByType(client, accountID, region, resourceType, out)
	if cc.isSkippableError(err) {
		slog.Debug("skipping resource type", "type", resourceType, "region", region, "error", err)
		return nil
	}
	if err != nil {
		slog.Warn("error listing resources", "type", resourceType, "region", region, "error", err)
		return err
	}

	return nil
}

func (cc *CloudControlEnumerator) listByType(
	client *cloudcontrol.Client,
	accountID,
	region,
	resourceType string,
	out *pipeline.P[output.AWSResource],
) error {
	var nextToken *string
	paginator := ratelimit.NewAWSPaginator()

	return paginator.Paginate(func() (bool, error) {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		result, err := client.ListResources(context.Background(), input)
		if err != nil {
			return true, fmt.Errorf("list %s: %w", resourceType, err)
		}

		for _, desc := range result.ResourceDescriptions {
			cr := awshelpers.CloudControlToAWSResource(desc, resourceType, accountID, region)
			out.Send(cr)
		}

		nextToken = result.NextToken
		return nextToken != nil, nil
	})
}

func (cc *CloudControlEnumerator) isSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException") ||
		strings.Contains(s, "AccessDeniedException")
}

func (cc *CloudControlEnumerator) newCloudControlClient(region string) (*cloudcontrol.Client, error) {
	awsCfg, err := cc.provider.GetAWSConfig(region)
	if err != nil {
		return nil, err
	}
	return cloudcontrol.NewFromConfig(*awsCfg), nil
}
