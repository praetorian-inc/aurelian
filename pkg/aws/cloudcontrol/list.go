package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
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
	options.Concurrency = max(1, options.Concurrency)

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

	resourceType, ok := types.ServiceToResourceType[parsed.Service]
	if !ok {
		return "", "", "", fmt.Errorf("unsupported arn service %q", parsed.Service)
	}

	region := parsed.Region
	if awshelpers.IsGlobalService(resourceType) {
		region = "us-east-1"
	}
	if region == "" {
		return "", "", "", fmt.Errorf("region not found in arn %q", resourceARN)
	}

	identifier := parsed.Resource
	if cc.arnIsIdentifier(resourceType) {
		identifier = resourceARN
	}

	return region, resourceType, identifier, nil
}

func (cc *CloudControlLister) arnIsIdentifier(resourceType string) bool {
	return slices.Contains([]string{
		"AWS::SNS::Topic",
	}, resourceType)
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

		for _, desc := range result.ResourceDescriptions {
			cr := awshelpers.CloudControlToAWSResource(desc, resourceType, accountID, region)
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
