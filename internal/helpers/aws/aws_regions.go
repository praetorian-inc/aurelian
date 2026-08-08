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
//
// A tier miss still degrades silently to the static list — failing on one would
// deny inventory to accounts that legitimately cannot reach the control plane,
// which is the bug LAB-5615 exists to fix. That reasoning is about the REMOTE
// end, and it does not extend to the caller: a static-fallback result reached
// under a done context is returned as an error, wrapping ctx.Err() so both
// errors.Is(err, context.Canceled) and errors.Is(err, context.DeadlineExceeded)
// work at the call site. When the caller has abandoned the work, both SDK calls
// fail with that same context error, and reporting the compiled-in list as a
// successful answer would fabricate coverage the ladder never fetched.
//
// The guard is deliberately narrow. A tier-1 or tier-2 success is real data that
// was actually retrieved, so it is returned even if the context finished
// afterwards; only the fabricated case is an error.
//
// It reads source from resolveRegions directly rather than routing through
// getEnabledRegionsWithSource, which would obtain the same value. The tier-3
// Warn no longer separates the two: that record lives in the shared
// resolveRegions, so this path emits it as well — which is the point, since this
// is the path both legacy entry points reach. What is left is that
// getEnabledRegionsWithSource already clones, so borrowing it would copy a list
// this function copies again on the way out.
func (r *RegionResolver) GetEnabledRegions(ctx context.Context) ([]string, error) {
	regions, source := r.resolveRegions(ctx)

	if source == output.SourceStaticFallback && ctx.Err() != nil {
		return nil, fmt.Errorf("region resolution canceled before any tier succeeded: %w", ctx.Err())
	}

	return slices.Clone(regions), nil
}

// getEnabledRegionsWithSource resolves enabled regions and reports which tier of
// the ladder produced them.
//
// Tier-3 logging does not distinguish this path from GetEnabledRegions. Both the
// Debug and the Warn sit in the shared resolveRegions, which both entry points
// reach, and the reasoning for the Warn's level lives there with it.
//
// Cloning does not distinguish it either. resolveRegions returns the package-level
// Regions variable itself at tier 3, and both entry points clone before handing it
// outward — see its doc comment. This path is not special in that respect.
//
// A tier miss is not an error on any path. Some accounts legitimately cannot
// reach the control plane, and failing on that would deny them inventory
// entirely — the problem LAB-5615 was filed to fix. The ladder degrades to the
// static list and the source is the signal instead.
//
// Here that is the whole story, because this function has no error return at
// all: whatever made the ladder fall through, a tier-3 source is the only thing
// observable on this path.
//
// The one case that IS an error is added by the two exported entry points that
// have an error to return — EnabledRegionsWithSource, which wraps this
// function, and GetEnabledRegions, which reaches the same state through
// resolveRegions. Each rejects a static-fallback result reached under an
// already-done context: the caller has abandoned the work, and handing back the
// compiled-in list as an answer would fabricate coverage no tier ever fetched.
//
// So the two are different categories rather than degrees of one. An
// unreachable control plane is the remote end failing, and only that degrades;
// an abandoned caller is this side giving up, and that is reported.
func (r *RegionResolver) getEnabledRegionsWithSource(ctx context.Context) ([]string, output.RegionSource) {
	regions, source := r.resolveRegions(ctx)

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
//
// A tier-3 return is also the one logged at Warn rather than only Debug, and the
// record sits here because both entry points reach it. Two of the three live
// production entry points reach tier 3 only through GetEnabledRegions — PostBind
// in pkg/plugin/aws_params.go and the CDK scan path through ResolveRegions in
// pkg/aws/cdk/scan.go — while the recon module takes EnabledRegionsWithSource as
// a func value and reaches it through getEnabledRegionsWithSource. Warning from
// either entry point alone would leave the other callers falling back silently.
//
// The level is Warn for reachability, not emphasis. configureSlog
// (cmd/generator.go) has exactly one call site and passes the literal "none",
// which maps to slog.LevelWarn. That level is hardcoded rather than selected, so
// the Debug line below is suppressed in the shipped binary. The Warn survives
// strictly more than that: SlogHandler.Enabled (pkg/plugin/log.go) does not simply
// compare against minLevel — it short-circuits `return true` for anything at Warn
// or above, falling through to the minLevel comparison only below Warn. The record
// therefore stands even if that hardcoded level is later raised to "error". A
// silent fallback is exactly the failure LAB-5615 exists to make visible, and Warn
// is the one level immune to the obvious future edit — making the logger quieter.
//
// The Warn is gated on ctx.Err() == nil. A static-fallback result reached under a
// done context is converted into an error before anything is scanned, so a "scan
// coverage may omit regions" record would describe work that never happens.
//
// That conversion lives at the two exported entry points, not at this function's
// two direct callers. GetEnabledRegions is both: it calls this function and holds
// the guard itself. The other direct caller, getEnabledRegionsWithSource, does not
// convert and cannot — it returns only regions and a source, with no error term to
// convert into. Its guard sits one frame further out, in EnabledRegionsWithSource,
// so its safety is inherited from that single production caller rather than held
// locally.
//
// The gap that leaves is concrete rather than hypothetical. A new caller of
// getEnabledRegionsWithSource, or of this function, that returns a tier-3 result
// successfully under a done context gets no Warn and no error, leaving exactly the
// silent fallback this record exists to expose.
//
// The gate races, and the race does not close at this layer or any other. This
// function can observe a live context, warn, and have the caller's guard observe a
// done one microseconds later — pairing the Warn with an error after all. That
// window is inherent to checking a context twice, and it is strictly narrower than
// warning unconditionally, where the pairing happened on every cancelled call
// rather than only on a race. Synchronising here would not remove it, because the
// context can finish after whichever check is last.
func (r *RegionResolver) resolveRegions(ctx context.Context) ([]string, output.RegionSource) {
	// Tier 1: Try AWS Account API first
	if r.accountClient != nil {
		regions, err := r.getEnabledRegionsFromAccount(ctx)
		if err == nil && len(regions) > 0 {
			slog.DebugContext(ctx, "Retrieved enabled regions from AWS Account API")
			return regions, output.SourceAccountAPI
		}
		slog.DebugContext(ctx, "Failed to get regions from AWS Account API, trying EC2", "error", err)
	}

	// Tier 2: Try EC2 API
	if r.ec2Client != nil {
		regions, err := r.getEnabledRegionsFromEC2(ctx)
		if err == nil && len(regions) > 0 {
			slog.DebugContext(ctx, "Retrieved enabled regions from EC2 API")
			return regions, output.SourceEC2API
		}
		slog.DebugContext(ctx, "Failed to get regions from EC2 API, using hardcoded list", "error", err)
	}

	// Tier 3: Fallback to hardcoded list
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
// caller's ctx, because NewAWSConfig delegates to newAWSConfigWith, which hands
// the loader a context.TODO() — and neither takes a context parameter to override
// it. The caller's ctx first takes effect at the getEnabledRegionsWithSource
// call, so it governs only the Account/EC2 API calls the ladder makes from there.
//
// Those are the calls that matter here. The coordinator calling this is a single
// point of failure for every downstream shard, and buildLoadOptions requests
// aws.RetryModeAdaptive for the config behind the clients newRegionResolver
// builds — without a cancellable context an unreachable endpoint would retry
// until the SDK budget is exhausted with no way to cancel.
//
// A config failure is returned as an error, since it is a caller problem rather
// than a tier miss. Once resolution starts, no tier failure is an error: it
// degrades to the static list, because failing here would generalize the very
// bug LAB-5615 exists to fix (accounts receiving no inventory at all).
//
// One caller-side case is an error, and it is not a tier failure. That
// degrade-silently rule is about the REMOTE end being unreachable; a
// caller-initiated cancellation is the opposite situation — the caller has
// abandoned the work. When the ctx threaded above is already done, both SDK
// calls fail with that context error, the ladder reaches tier 3, and returning
// the compiled-in list with a nil error would hand an abandoned coordinator
// fabricated coverage to fan every downstream shard across. So a static-fallback
// result under a done context returns an error wrapping ctx.Err(), which keeps
// errors.Is(err, context.Canceled) and errors.Is(err, context.DeadlineExceeded)
// working at the call site. Reporting success there would also undercut this
// function's own rationale for threading ctx at all: cancellation would abort
// the SDK retries and then be reported as an answer.
//
// The guard is scoped to the fabricated case only, not to ctx.Err() != nil. A
// tier-1 or tier-2 success is data the ladder actually fetched, and returning it
// is correct even if the context finished afterwards.
func EnabledRegionsWithSource(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error) {
	resolver, err := newRegionResolver(profile, profileDir)
	if err != nil {
		return nil, "", err
	}

	regions, source := resolver.getEnabledRegionsWithSource(ctx)
	if source == output.SourceStaticFallback && ctx.Err() != nil {
		return nil, "", fmt.Errorf("region resolution canceled before any tier succeeded: %w", ctx.Err())
	}

	return regions, source, nil
}
