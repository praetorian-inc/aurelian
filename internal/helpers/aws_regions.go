package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

var Regions = []string{
	"us-east-2",
	"us-east-1",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"ap-east-1",
	"ap-south-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"ap-south-1",
	"ap-northeast-3",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"ca-west-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-south-1",
	"eu-west-3",
	"eu-south-2",
	"eu-north-1",
	"eu-central-2",
	"il-central-1",
	"me-south-1",
	"me-central-1",
	"sa-east-1",
	"us-gov-east-1",
	"us-gov-west-1",
}

func EnabledRegions(profile string, opts []*types.Option) ([]string, error) {
	var regions []string

	// Check if cache is disabled
	disableCacheOpt := options.GetOptionByName(options.AwsDisableCacheOpt.Name, opts)
	cacheDisabled := false
	if disableCacheOpt != nil {
		var err error
		cacheDisabled, err = strconv.ParseBool(disableCacheOpt.Value)
		if err != nil {
			slog.Warn("Failed to parse disable-cache option, defaulting to false", "error", err)
			cacheDisabled = false
		}
	}

	// Use cache if it exists for profile and cache is not disabled
	if !cacheDisabled {
		cachedRegionsFile := utils.CreateCachedFileName(fmt.Sprintf("%s_enabled_regions", profile))
		if utils.IsCacheValid(cachedRegionsFile) {
			data, err := utils.ReadCache(cachedRegionsFile)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal(data, &regions)
			if err != nil {
				return nil, err
			}
			slog.Debug("Using cached enabled regions")
			return regions, nil
		}
	}

	cfg, err := GetAWSCfg("us-east-1", profile, opts)
	if err != nil {
		return nil, err
	}

	// Tier 1: Try AWS Account API first
	regions, err = getEnabledRegionsFromAccount(cfg)
	if err == nil && len(regions) > 0 {
		slog.Debug("Retrieved enabled regions from AWS Account API")
		return cacheAndReturnRegions(profile, regions, cacheDisabled)
	}
	slog.Debug("Failed to get regions from AWS Account API, trying EC2", "error", err)

	// Tier 2: Try EC2 API
	regions, err = getEnabledRegionsFromEC2(cfg)
	if err == nil && len(regions) > 0 {
		slog.Debug("Retrieved enabled regions from EC2 API")
		return cacheAndReturnRegions(profile, regions, cacheDisabled)
	}
	slog.Debug("Failed to get regions from EC2 API, using hardcoded list", "error", err)

	// Tier 3: Fallback to hardcoded list
	slog.Debug("Using hardcoded region list as fallback")
	return cacheAndReturnRegions(profile, Regions, cacheDisabled)
}

// getEnabledRegionsFromAccount attempts to get enabled regions using AWS Account API
func getEnabledRegionsFromAccount(cfg aws.Config) ([]string, error) {
	var regions []string
	
	accountClient := account.NewFromConfig(cfg)
	
	paginator := account.NewListRegionsPaginator(accountClient, &account.ListRegionsInput{
		RegionOptStatusContains: []awstypes.RegionOptStatus{
			awstypes.RegionOptStatusEnabled,
			awstypes.RegionOptStatusEnabledByDefault,
		},
	})
	
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to list regions from account API: %w", err)
		}

		for _, region := range result.Regions {
			if region.RegionName != nil {
				regions = append(regions, *region.RegionName)
			}
		}
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("no enabled regions found from account API")
	}

	return regions, nil
}

// getEnabledRegionsFromEC2 attempts to get enabled regions using EC2 API
func getEnabledRegionsFromEC2(cfg aws.Config) ([]string, error) {
	var regions []string

	client := ec2.NewFromConfig(cfg)
	input := &ec2.DescribeRegionsInput{}

	result, err := client.DescribeRegions(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions from EC2 API: %w", err)
	}

	for _, region := range result.Regions {
		if region.RegionName != nil {
			regions = append(regions, *region.RegionName)
		}
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("no regions found from EC2 API")
	}

	return regions, nil
}

// cacheAndReturnRegions caches the regions if caching is enabled and returns them
func cacheAndReturnRegions(profile string, regions []string, cacheDisabled bool) ([]string, error) {
	
	if !cacheDisabled {
		data, err := json.Marshal(regions)
		if err != nil {
			slog.Warn("Failed to marshal regions for caching", "error", err)
		} else {
			cachedRegionsFile := utils.CreateCachedFileName(fmt.Sprintf("%s_enabled_regions", profile))
			err = utils.WriteCache(cachedRegionsFile, data)
			if err != nil {
				slog.Warn("Failed to write regions to cache", "error", err)
			} else {
				slog.Debug("Cached enabled regions", "count", len(regions))
			}
		}
	}

	return regions, nil
}