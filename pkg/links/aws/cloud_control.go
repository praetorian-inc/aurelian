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
	"github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSCloudControl struct {
	*chain.Base
	semaphores          map[string]chan struct{}
	regions             []string
	profile             string
	wg                  sync.WaitGroup
	cloudControlClients map[string]*cloudcontrol.Client
}

func (a *AWSCloudControl) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "AWS CloudControl"}
}

func (a *AWSCloudControl) Params() []cfg.Param {
	return []cfg.Param{
		opts.AWSRegions(),
		opts.AWSProfile(),
	}
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg: sync.WaitGroup{},
	}
	cc.Base = chain.NewBase(cc, configs...)

	return cc
}

func (a *AWSCloudControl) initializeSemaphores() {
	a.semaphores = make(map[string]chan struct{})
	for _, region := range a.regions {
		a.semaphores[region] = make(chan struct{}, 5)
	}
}

func (a *AWSCloudControl) initializeClients() error {
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)

	for _, region := range a.regions {
		config, err := util.GetAWSConfig(region, a.profile)
		if err != nil {
			return fmt.Errorf("failed to create AWS config: %w", err)
		}

		a.cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
	}

	return nil
}

func (a *AWSCloudControl) Initialize() error {
	a.ContextHolder = cfg.NewContextHolder()
	regions, err := cfg.As[[]string](a.Arg("regions"))
	slog.Debug("cloudcontrol regions", "regions", regions)
	if err != nil || len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		regions = util.Regions
	}
	a.regions = regions
	a.initializeClients()
	a.initializeSemaphores()

	profile, err := cfg.As[string](a.Arg("profile"))
	slog.Debug("cloudcontrol profile", "profile", profile)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}
	a.profile = profile

	slog.Debug("cloudcontrol initialized", "regions", a.regions, "profile", a.profile)

	return nil
}

func (a *AWSCloudControl) Process(resourceType string) error {
	for _, region := range a.regions {
		if a.isGlobalService(resourceType, region) {
			slog.Info("Skipping global service", "type", resourceType, "region", region)
			continue
		}

		a.wg.Add(1)
		go a.listResourcesInRegion(resourceType, region)
	}

	a.wg.Wait()
	return nil
}

func (a *AWSCloudControl) isGlobalService(resourceType, region string) bool {
	return util.IsGlobalService(resourceType) && region != "us-east-1"
}

func (a *AWSCloudControl) listResourcesInRegion(resourceType, region string) {
	defer a.wg.Done()
	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.profile)

	config, err := util.GetAWSConfig(region, a.profile)
	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return
	}

	accountId, err := util.GetAccountId(config)
	if err != nil {
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
			errMsg := err.Error()
			// Check for different error types
			switch {
			case strings.Contains(errMsg, "TypeNotFoundException"):
				slog.Debug(fmt.Sprintf("The type %s is not available in region %s", resourceType, region))
				break

			case strings.Contains(errMsg, "is not authorized to perform") || strings.Contains(errMsg, "AccessDeniedException"):
				slog.Error(fmt.Sprintf("Access denied to list resources of type %s in region %s", resourceType, region))
				slog.Debug(errMsg)
				break

			case strings.Contains(errMsg, "UnsupportedActionException"):
				slog.Info(fmt.Sprintf("The type %s is not supported in region %s", resourceType, region))
				break

			case strings.Contains(errMsg, "ThrottlingException"):
				// Log throttling but don't terminate - let AWS SDK retry with backoff
				slog.Info("Rate limited", slog.String("region", region), slog.String("type", resourceType))
				continue

			default:
				slog.Error("Failed to ListResources",
					slog.String("region", region),
					slog.String("type", resourceType),
					slog.String("err", errMsg))
			}
			// For non-terminal errors, continue to next page
			continue
		}

		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)
			slog.Debug("Sending resource", "resource", erd)
			a.sendResource(erd)
		}

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

func (a *AWSCloudControl) sendResource(resource *types.EnrichedResourceDescription) {
	sem := a.semaphores[resource.Region]
	sem <- struct{}{}

	defer func() { <-sem }()

	a.Send(resource)
}
