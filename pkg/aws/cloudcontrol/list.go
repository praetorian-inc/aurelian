package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

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
)

type CloudControlLister struct {
	plugin.AWSCommonRecon
	CrossRegionActor *ratelimit.CrossRegionActor
	AWSConfigs       map[string]*aws.Config
	configMu         sync.RWMutex
	accountID        string
	accountIDOnce    sync.Once
	accountIDErr     error
}

func NewCloudControlLister(options plugin.AWSCommonRecon) *CloudControlLister {
	return &CloudControlLister{
		AWSCommonRecon:   options,
		CrossRegionActor: ratelimit.NewCrossRegionActor(options.Concurrency),
		AWSConfigs:       make(map[string]*aws.Config),
	}
}

func (cc *CloudControlLister) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	_, err := awsaarn.Parse(identifier)
	if err == nil {
		return cc.ListByARN(identifier, out)
	}

	isResourceType := strings.HasPrefix(identifier, "AWS::")
	if isResourceType {
		return cc.ListByType(identifier, out)
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

func (cc *CloudControlLister) ListByARN(resourceARN string, out *pipeline.P[output.AWSResource]) error {
	resource, err := cc.getResourceByARN(resourceARN)
	if cc.isSkippableError(err) {
		slog.Debug("skipping arn", "arn", resourceARN, "error", err)
		return nil
	}

	out.Send(resource)

	return err
}

func (cc *CloudControlLister) getResourceByARN(arn string) (output.AWSResource, error) {
	region, resourceType, identifier, err := cc.resolveARNTarget(arn)
	if err != nil {
		return output.AWSResource{}, err
	}

	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.getAccountID(region)
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

func (cc *CloudControlLister) resolveARNTarget(resourceARN string) (string, string, string, error) {
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
func (cc *CloudControlLister) resolveResourceRegion(parsed awsaarn.ARN, resourceType string) (string, error) {
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
func (cc *CloudControlLister) resolveS3BucketRegion(bucketName string) (string, error) {
	// GetBucketLocation can be called from any region.
	awsCfg, err := cc.getAWSConfig("us-east-1")
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

func (cc *CloudControlLister) requiresSpecialIdentifier(resourceType, resourceARN, resourceID string) (string, bool) {
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

func (cc *CloudControlLister) parseAsARN(resourceARN, _ string) string {
	return resourceARN
}

func (cc *CloudControlLister) parseEC2InstanceID(_, instanceID string) string {
	// example: instance/i-123456789012
	parts := strings.Split(instanceID, "/")
	if len(parts) != 2 {
		return instanceID
	}

	return parts[1]
}

func (cc *CloudControlLister) parseCloudFormationStackID(_, stackID string) string {
	// example: stack/StackSet-Chariot-Deployment-a00b9d08-b877-4781-a772-c3f798f5eeac/f6eecfa0-837a-11f0-aa31-0affe997852d
	parts := strings.Split(stackID, "/")
	if len(parts) < 2 {
		return stackID
	}

	return parts[1]
}

func (cc *CloudControlLister) parseTaskDefinition(_, taskDefinition string) string {
	// example: task-definition/aurelian-sec-c22f7fe9-secret-task:1
	parts := strings.Split(taskDefinition, "/")
	if len(parts) < 2 {
		return taskDefinition
	}
	return parts[1]
}

// ListByType enumerates a single resource type across all regions, emitting each
// resource into out as pages are fetched. Its signature matches the fn
// parameter of pipeline.Pipe[string, output.AWSResource].
func (cc *CloudControlLister) ListByType(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if len(cc.AWSCommonRecon.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	actor := ratelimit.NewCrossRegionActor(cc.Concurrency)
	return actor.ActInRegions(cc.AWSCommonRecon.Regions, func(region string) error {
		return cc.listInRegionByType(region, resourceType, out)
	})
}

func (cc *CloudControlLister) listInRegionByType(region, resourceType string, out *pipeline.P[output.AWSResource]) error {
	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.getAccountID(region)
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

func (cc *CloudControlLister) listByType(
	client *cloudcontrol.Client,
	accountID,
	region,
	resourceType string,
	out *pipeline.P[output.AWSResource],
) error {
	var nextToken *string
	paginator := ratelimit.NewPaginator()

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

		filter := resourceFilters[resourceType]
		for _, desc := range result.ResourceDescriptions {
			cr := awshelpers.CloudControlToAWSResource(desc, resourceType, accountID, region)
			if filter != nil && !filter(cr) {
				continue
			}
			out.Send(cr)
		}

		nextToken = result.NextToken
		return nextToken != nil, nil
	})
}

func (cc *CloudControlLister) isSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException") ||
		strings.Contains(s, "AccessDeniedException")
}

func (cc *CloudControlLister) newCloudControlClient(region string) (*cloudcontrol.Client, error) {
	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		return nil, err
	}
	return cloudcontrol.NewFromConfig(*awsCfg), nil
}

func (cc *CloudControlLister) getAccountID(region string) (string, error) {
	cc.accountIDOnce.Do(func() {
		awsCfg, err := cc.getAWSConfig(region)
		if err != nil {
			cc.accountIDErr = err
			return
		}
		cc.accountID, cc.accountIDErr = awshelpers.GetAccountId(*awsCfg)
	})
	return cc.accountID, cc.accountIDErr
}

func (cc *CloudControlLister) getAWSConfig(region string) (*aws.Config, error) {
	cc.configMu.RLock()
	if cfg, ok := cc.AWSConfigs[region]; ok {
		cc.configMu.RUnlock()
		return cfg, nil
	}
	cc.configMu.RUnlock()

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    cc.Profile,
		ProfileDir: cc.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	cc.configMu.Lock()
	cc.AWSConfigs[region] = &awsCfg
	cc.configMu.Unlock()

	return &awsCfg, nil
}
