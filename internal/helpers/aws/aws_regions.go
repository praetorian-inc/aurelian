package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/account"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/aurelian/pkg/output"
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
	regions, _ := r.resolveRegions(ctx)
	return slices.Clone(regions), nil
}

// getEnabledRegionsWithSource resolves enabled regions and reports which tier of
// the ladder produced them.
//
// One thing differs from GetEnabledRegions, and it belongs on this path only: a
// tier-3 result is logged at Warn as well as Debug — the Debug sits in the shared
// resolveRegions, which both entry points reach. configureSlog (cmd/generator.go)
// has exactly one call site, and it passes the literal "none", which maps to
// slog.LevelWarn. That level is hardcoded rather than selected, so the Debug line
// is suppressed in the shipped binary.
//
// The Warn survives strictly more than that. SlogHandler.Enabled (pkg/plugin/log.go)
// does not simply compare against minLevel: it short-circuits `return true` for
// anything at Warn or above, falling through to the minLevel comparison only below
// Warn. The record therefore stands even if that hardcoded level is later raised to
// "error". A silent fallback is exactly the failure LAB-5615 exists to make visible,
// and Warn is the one level immune to the obvious future edit — making the logger
// quieter.
//
// Cloning is NOT such a difference. resolveRegions returns the package-level
// Regions variable itself at tier 3, and both entry points clone before handing it
// outward — see its doc comment. This path is not special in that respect.
//
// A tier-3 result is not an error. Some accounts legitimately cannot reach the
// control plane, and failing here would deny them inventory entirely — the problem
// LAB-5615 was filed to fix. The source is the signal instead.
func (r *RegionResolver) getEnabledRegionsWithSource(ctx context.Context) ([]string, output.RegionSource) {
	regions, source := r.resolveRegions(ctx)

	if source == output.SourceStaticFallback {
		slog.WarnContext(ctx, "AWS region enumeration fell back to the compiled-in region list; "+
			"scan coverage may omit regions enabled for this account and may include regions it has not enabled",
			"source", string(source),
			"region_count", len(regions),
		)
	}

	return slices.Clone(regions), source
}

// resolveRegions walks the tiered fallback ladder and reports both the regions
// and the tier that produced them. The tier is determined here, where it is
// known, rather than inferred by a caller comparing against the static list.
//
// The ladder always yields a list, so there is no error to return: tier 3
// cannot fail. Callers that must expose an error signature supply their own.
//
// A tier-3 return is the package-level Regions variable itself, not a copy.
// Callers that hand the result outward must clone it.
func (r *RegionResolver) resolveRegions(ctx context.Context) ([]string, output.RegionSource) {
	// Tier 1: Try AWS Account API first
	if r.accountClient != nil {
		regions, err := r.getEnabledRegionsFromAccount(ctx)
		if err == nil && len(regions) > 0 {
			slog.Debug("Retrieved enabled regions from AWS Account API")
			return regions, output.SourceAccountAPI
		}
		slog.Debug("Failed to get regions from AWS Account API, trying EC2", "error", err)
	}

	// Tier 2: Try EC2 API
	if r.ec2Client != nil {
		regions, err := r.getEnabledRegionsFromEC2(ctx)
		if err == nil && len(regions) > 0 {
			slog.Debug("Retrieved enabled regions from EC2 API")
			return regions, output.SourceEC2API
		}
		slog.Debug("Failed to get regions from EC2 API, using hardcoded list", "error", err)
	}

	// Tier 3: Fallback to hardcoded list
	slog.Debug("Using hardcoded region list as fallback")
	return Regions, output.SourceStaticFallback
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

// newRegionResolver builds a RegionResolver backed by real AWS clients. It is the
// single place both public entry points construct that resolver, so a change to
// the config input cannot be applied to one path and silently missed on the other.
//
// It returns (nil, err) on a config failure; callers adapt that to their own
// signature, which differs between the two entry points.
func newRegionResolver(profile, profileDir string) (*RegionResolver, error) {
	cfg, err := NewAWSConfig(AWSConfigInput{
		Region:     "us-east-1",
		Profile:    profile,
		ProfileDir: profileDir,
	})
	if err != nil {
		return nil, err
	}

	return &RegionResolver{
		accountClient: account.NewFromConfig(cfg),
		ec2Client:     ec2.NewFromConfig(cfg),
	}, nil
}

// EnabledRegions returns the list of enabled AWS regions for the given profile.
// It uses NewAWSConfig to get credentials and then queries AWS APIs.
// Signature changed: accepts profile and profileDir directly instead of []*types.Option.
func EnabledRegions(profile string, profileDir string) ([]string, error) {
	resolver, err := newRegionResolver(profile, profileDir)
	if err != nil {
		return nil, err
	}

	return resolver.GetEnabledRegions(context.TODO())
}

// EnabledRegionsWithSource returns the enabled AWS regions for the given profile
// together with the provenance of that list.
//
// Unlike EnabledRegions, it threads the caller's context into the region-tier
// SDK calls rather than using context.TODO(). That scope is exact, and narrower
// than "the SDK calls": the config load inside newRegionResolver does NOT see the
// caller's ctx, because NewAWSConfig hands its own loader a context.TODO()
// internally and takes no context parameter to override it. The caller's ctx
// first takes effect at the getEnabledRegionsWithSource call, so it governs only
// the Account/EC2 API calls the ladder makes from there.
//
// Those are the calls that matter here. The coordinator calling this is a single
// point of failure for every downstream shard, and NewAWSConfig requests
// aws.RetryModeAdaptive for the clients newRegionResolver builds — without a
// cancellable context an unreachable endpoint would retry until the SDK budget is
// exhausted with no way to cancel.
//
// A config failure is returned as an error, since it is a caller problem rather
// than a tier miss. Once resolution starts, no tier failure is an error: it
// degrades to the static list, because failing here would generalize the very
// bug LAB-5615 exists to fix (accounts receiving no inventory at all).
func EnabledRegionsWithSource(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error) {
	resolver, err := newRegionResolver(profile, profileDir)
	if err != nil {
		return nil, "", err
	}

	regions, source := resolver.getEnabledRegionsWithSource(ctx)
	return regions, source, nil
}
