package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/account"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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

// AccountRegionLister abstracts AWS Account API for region listing
type AccountRegionLister interface {
	ListRegions(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error)
}

// EC2RegionLister abstracts AWS EC2 API for region listing
type EC2RegionLister interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// RegionResolver resolves enabled AWS regions using a tiered fallback strategy
type RegionResolver struct {
	accountClient AccountRegionLister
	ec2Client     EC2RegionLister
}

// GetEnabledRegions retrieves enabled regions using tiered fallback:
// Tier 1: AWS Account API
// Tier 2: EC2 API
// Tier 3: Hardcoded Regions list
func (r *RegionResolver) GetEnabledRegions(ctx context.Context) ([]string, error) {
	// Tier 1: Try AWS Account API first
	if r.accountClient != nil {
		regions, err := r.getEnabledRegionsFromAccount(ctx)
		if err == nil && len(regions) > 0 {
			slog.Debug("Retrieved enabled regions from AWS Account API")
			return regions, nil
		}
		slog.Debug("Failed to get regions from AWS Account API, trying EC2", "error", err)
	}

	// Tier 2: Try EC2 API
	if r.ec2Client != nil {
		regions, err := r.getEnabledRegionsFromEC2(ctx)
		if err == nil && len(regions) > 0 {
			slog.Debug("Retrieved enabled regions from EC2 API")
			return regions, nil
		}
		slog.Debug("Failed to get regions from EC2 API, using hardcoded list", "error", err)
	}

	// Tier 3: Fallback to hardcoded list
	slog.Debug("Using hardcoded region list as fallback")
	return Regions, nil
}

// getEnabledRegionsFromAccount attempts to get enabled regions using AWS Account API
func (r *RegionResolver) getEnabledRegionsFromAccount(ctx context.Context) ([]string, error) {
	var regions []string

	paginator := account.NewListRegionsPaginator(r.accountClient, &account.ListRegionsInput{
		RegionOptStatusContains: []awstypes.RegionOptStatus{
			awstypes.RegionOptStatusEnabled,
			awstypes.RegionOptStatusEnabledByDefault,
		},
	})

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
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
func (r *RegionResolver) getEnabledRegionsFromEC2(ctx context.Context) ([]string, error) {
	var regions []string

	input := &ec2.DescribeRegionsInput{}
	result, err := r.ec2Client.DescribeRegions(ctx, input)
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

// ResolveRegions expands a regions slice, replacing ["all"] with the actual
// enabled region list via STS. Returns the input unchanged if not ["all"].
func ResolveRegions(regions []string, profile, profileDir string) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return EnabledRegions(profile, profileDir)
	}
	return regions, nil
}

// EnabledRegions returns the list of enabled AWS regions for the given profile.
// It uses NewAWSConfig to get credentials and then queries AWS APIs.
// Signature changed: accepts profile and profileDir directly instead of []*types.Option.
func EnabledRegions(profile string, profileDir string) ([]string, error) {
	// Use NewAWSConfig to get AWS configuration
	cfg, err := NewAWSConfig(AWSConfigInput{
		Region:     "us-east-1",
		Profile:    profile,
		ProfileDir: profileDir,
	})
	if err != nil {
		return nil, err
	}

	// Create resolver with real AWS clients
	resolver := &RegionResolver{
		accountClient: account.NewFromConfig(cfg),
		ec2Client:     ec2.NewFromConfig(cfg),
	}

	return resolver.GetEnabledRegions(context.TODO())
}
