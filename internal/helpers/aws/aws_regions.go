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

type AccountRegionLister interface {
	ListRegions(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error)
}

type EC2RegionLister interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// RegionResolver resolves enabled AWS regions through a tiered fallback ladder.
type RegionResolver struct {
	accountClient AccountRegionLister
	ec2Client     EC2RegionLister
}

// GetEnabledRegions returns the enabled regions for the resolver's account.
func (r *RegionResolver) GetEnabledRegions(ctx context.Context) ([]string, error) {
	regions, source := r.resolveRegions(ctx)

	if fabricatedUnderDoneContext(ctx, source) {
		return nil, fmt.Errorf("region resolution abandoned before any tier succeeded: %w", ctx.Err())
	}

	return slices.Clone(regions), nil
}

func (r *RegionResolver) getEnabledRegionsWithSource(ctx context.Context) ([]string, output.RegionSource) {
	regions, source := r.resolveRegions(ctx)

	return slices.Clone(regions), source
}

// fabricatedUnderDoneContext reports whether the ladder produced the compiled-in
// list for a caller that had already given up.
//
// A tier miss degrades to that list deliberately, so an account that
// legitimately cannot reach the control plane still gets an inventory;
// denying it one is the bug LAB-5615 exists to fix. That reasoning covers the
// remote end failing and does not extend to this side giving up — handing the
// compiled-in list to an abandoned caller would report coverage no tier ever
// fetched. Tier-1 and tier-2 results are data the ladder really retrieved, so
// they stay valid even if the context finishes afterwards.
func fabricatedUnderDoneContext(ctx context.Context, source output.RegionSource) bool {
	return source == output.SourceStaticFallback && ctx.Err() != nil
}

// resolveRegions walks the fallback ladder and reports which tier produced the
// regions. Tier 3 cannot fail, so there is no error to return.
//
// A tier-3 return is the package-level Regions slice itself rather than a copy;
// callers handing the result outward must clone it.
//
// Tier 3 logs at Warn rather than only Debug because a silent fallback is the
// failure LAB-5615 exists to make visible, and Warn survives the obvious future
// edit of making the logger quieter. The Warn is skipped under a done context:
// the exported entry points turn that result into an error, so no scan follows.
// Checking the context here and again at the guard can race, which is strictly
// narrower than warning unconditionally and is not closable at any layer.
func (r *RegionResolver) resolveRegions(ctx context.Context) ([]string, output.RegionSource) {
	if r.accountClient != nil {
		regions, err := r.getEnabledRegionsFromAccount(ctx)
		if err == nil && len(regions) > 0 {
			slog.DebugContext(ctx, "Retrieved enabled regions from AWS Account API")
			return regions, output.SourceAccountAPI
		}
		slog.DebugContext(ctx, "Failed to get regions from AWS Account API, trying EC2", "error", err)
	}

	if r.ec2Client != nil {
		regions, err := r.getEnabledRegionsFromEC2(ctx)
		if err == nil && len(regions) > 0 {
			slog.DebugContext(ctx, "Retrieved enabled regions from EC2 API")
			return regions, output.SourceEC2API
		}
		slog.DebugContext(ctx, "Failed to get regions from EC2 API, using hardcoded list", "error", err)
	}

	slog.DebugContext(ctx, "Using hardcoded region list as fallback")
	if ctx.Err() == nil {
		slog.WarnContext(ctx, "AWS region enumeration fell back to the compiled-in region list; "+
			"scan coverage may omit regions enabled for this account and may include regions it has not enabled",
			"source", string(output.SourceStaticFallback),
			"region_count", len(Regions),
		)
	}
	return Regions, output.SourceStaticFallback
}

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

// ResolveRegions replaces the ["all"] sentinel with the enabled region list, and
// returns any other input unchanged.
func ResolveRegions(regions []string, profile, profileDir string) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return EnabledRegions(profile, profileDir)
	}
	return regions, nil
}

// newRegionResolver is the single construction point for both exported entry
// points, so a change to the config input cannot be applied to one and silently
// missed on the other.
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

// EnabledRegions returns the enabled AWS regions for the given profile.
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
// Unlike EnabledRegions it threads the caller's context into the Account/EC2 tier
// calls, which matters because buildLoadOptions requests aws.RetryModeAdaptive:
// without a cancellable context an unreachable endpoint retries until the SDK
// budget is exhausted. The scope is narrower than "the SDK calls" — the config
// load inside newRegionResolver hands the loader its own context.TODO() and takes
// no context parameter to override it, so ctx first takes effect below.
func EnabledRegionsWithSource(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error) {
	resolver, err := newRegionResolver(profile, profileDir)
	if err != nil {
		return nil, "", err
	}

	regions, source := resolver.getEnabledRegionsWithSource(ctx)
	if fabricatedUnderDoneContext(ctx, source) {
		return nil, "", fmt.Errorf("region resolution abandoned before any tier succeeded: %w", ctx.Err())
	}

	return regions, source, nil
}
