package aws

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/util"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSCloudControl struct {
	base.AwsReconLink
	semaphores          map[string]chan struct{}
	wg                  sync.WaitGroup
	cloudControlClients map[string]*cloudcontrol.Client
}

func (a *AWSCloudControl) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "AWS CloudControl"}
}

func (a *AWSCloudControl) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())

	return params
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg: sync.WaitGroup{},
	}
	cc.Base = chain.NewBase(cc, configs...)

	return cc
}

func (a *AWSCloudControl) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	a.initializeClients()
	a.initializeSemaphores()
	return nil
}

func (a *AWSCloudControl) initializeSemaphores() {
	a.semaphores = make(map[string]chan struct{})
	for _, region := range a.Regions {
		a.semaphores[region] = make(chan struct{}, 5)
	}
	a.semaphores[""] = make(chan struct{}, 5) // global region
}

func (a *AWSCloudControl) initializeClients() error {
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)

	for _, region := range a.Regions {
		config, err := helpers.GetAWSCfg(region, a.Profile, options.JanusParamAdapter(a.Params()))
		if err != nil {
			return fmt.Errorf("failed to create AWS config: %w", err)
		}

		a.cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
	}

	return nil
}

func (a *AWSCloudControl) Process(resourceType string) error {
	for _, region := range a.Regions {
		if a.isGlobalService(resourceType, region) {
			slog.Info("Skipping global service", "type", resourceType, "region", region)
			continue
		}

		a.wg.Add(1)
		go a.listResourcesInRegion(resourceType, region)
	}

	a.wg.Wait()
	slog.Debug("cloudcontrol complete")
	return nil
}

func (a *AWSCloudControl) isGlobalService(resourceType, region string) bool {
	return util.IsGlobalService(resourceType) && region != "us-east-1"
}

func (a *AWSCloudControl) listResourcesInRegion(resourceType, region string) {
	defer a.wg.Done()

	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.Profile)

	config, err := helpers.GetAWSCfg(region, a.Profile, options.JanusParamAdapter(a.Params()))

	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return
	}

	accountId, err := util.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err, "region", region)
		return
	}

	cc := a.cloudControlClients[region]

	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		res, err := paginator.NextPage(a.Context())

		if err != nil {
			err, shouldBreak := a.processError(resourceType, region, err)
			if err != nil {
				slog.Error("Failed to list resources", "error", err)
				return
			}

			if shouldBreak {
				break
			}
		}

		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)
			a.sendResource(region, erd)
		}

	}
}

func (a *AWSCloudControl) processError(resourceType, region string, err error) (error, bool) {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "TypeNotFoundException"):
		return fmt.Errorf("%s is not available in region %s", resourceType, region), true

	case strings.Contains(errMsg, "is not authorized to perform") || strings.Contains(errMsg, "AccessDeniedException"):
		return fmt.Errorf("access denied to list resources of type %s in region %s: %s", resourceType, region, errMsg), true

	case strings.Contains(errMsg, "UnsupportedActionException"):
		return fmt.Errorf("the type %s is not supported in region %s", resourceType, region), true

	case strings.Contains(errMsg, "ThrottlingException"):
		// Log throttling but don't terminate - let AWS SDK retry with backoff
		return fmt.Errorf("rate limited: %s", errMsg), false

	default:
		return fmt.Errorf("failed to ListResources of type %s in region %s: %w", resourceType, region, err), false
	}
}

func (a *AWSCloudControl) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) *types.EnrichedResourceDescription {
	var erdRegion string
	if helpers.IsGlobalService(rType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	erd := types.EnrichedResourceDescription{
		Identifier: *resource.Identifier,
		TypeName:   rType,
		Region:     erdRegion,
		Properties: *resource.Properties,
		AccountId:  accountId,
	}

	// some resources have a different ARN format than the identifier
	// so we need to parse the identifier to get the ARN
	parsed, err := arn.Parse(*resource.Identifier)
	if err != nil {
		slog.Debug("Failed to parse ARN: "+*resource.Identifier, slog.String("error", err.Error()))
		erd.Arn = erd.ToArn()
	} else {
		slog.Debug("Parsed ARN: "+*resource.Identifier, slog.String("arn", parsed.String()))
		erd.Arn = parsed
	}

	erd.Arn = erd.ToArn()

	return &erd

}

func (a *AWSCloudControl) sendResource(region string, resource *types.EnrichedResourceDescription) {
	sem := a.semaphores[region]
	sem <- struct{}{}

	defer func() { <-sem }()

	a.Send(resource)
}

func (a *AWSCloudControl) Complete() error {
	a.wg.Wait()
	return nil
}
