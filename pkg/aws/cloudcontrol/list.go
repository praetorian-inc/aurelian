package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
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
	if options.Concurrency <= 0 {
		options.Concurrency = 1
	}

	return &CloudControlLister{
		AWSCommonRecon:   options,
		CrossRegionActor: ratelimit.NewCrossRegionActor(options.Concurrency),
		AWSConfigs:       make(map[string]*aws.Config),
	}
}


// List enumerates a single resource type across all regions, emitting each
// resource into out as pages are fetched. Its signature matches the fn
// parameter of pipeline.Pipe[string, output.AWSResource].
func (cc *CloudControlLister) List(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if len(cc.AWSCommonRecon.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	actor := ratelimit.NewCrossRegionActor(cc.Concurrency)
	return actor.ActInRegions(cc.AWSCommonRecon.Regions, func(region string) error {
		return cc.listInRegion(region, resourceType, out)
	})
}

func (cc *CloudControlLister) listInRegion(region, resourceType string, out *pipeline.P[output.AWSResource]) error {
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
	} else if err != nil {
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
