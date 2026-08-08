package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testability

type mockAccountClient struct {
	listRegionsFunc func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error)
}

func (m *mockAccountClient) ListRegions(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	if m.listRegionsFunc != nil {
		return m.listRegionsFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("not implemented")
}

type mockEC2Client struct {
	describeRegionsFunc func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

func (m *mockEC2Client) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if m.describeRegionsFunc != nil {
		return m.describeRegionsFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("not implemented")
}

func TestEnabledRegions_AccountAPISuccess(t *testing.T) {
	// Setup mock Account API that returns regions
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			usEast1 := "us-east-1"
			usWest2 := "us-west-2"
			return &account.ListRegionsOutput{
				Regions: []awstypes.Region{
					{RegionName: &usEast1},
					{RegionName: &usWest2},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, regions)
}

func TestEnabledRegions_AccountAPIFails_FallsBackToEC2(t *testing.T) {
	// Account API fails
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

	// EC2 API succeeds
	mockEC2 := &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			usEast1 := "us-east-1"
			euWest1 := "eu-west-1"
			return &ec2.DescribeRegionsOutput{
				Regions: []ec2types.Region{
					{RegionName: &usEast1},
					{RegionName: &euWest1},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
		ec2Client:     mockEC2,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "eu-west-1"}, regions)
}

func TestEnabledRegions_BothAPIsFail_FallsBackToHardcoded(t *testing.T) {
	// Account API fails
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

	// EC2 API fails
	mockEC2 := &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			return nil, fmt.Errorf("ec2 API error")
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
		ec2Client:     mockEC2,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	// Should fallback to hardcoded Regions list
	assert.Equal(t, Regions, regions)
	assert.Greater(t, len(regions), 0, "hardcoded Regions list should not be empty")
}

func TestEnabledRegions_FullTieredFallback(t *testing.T) {
	// There is no expected-provenance column. GetEnabledRegions returns
	// ([]string, error) and never reports which tier produced the list, so a
	// row could only carry a tier name the loop body has no way to check —
	// which is what the deleted expectedFallback field was. Provenance IS
	// asserted, on the entry point that actually returns it, in
	// TestGetEnabledRegionsWithSource_ReportsTier.
	tests := []struct {
		name            string
		accountError    error
		accountRegions  []string
		ec2Error        error
		ec2Regions      []string
		expectedRegions []string
	}{
		{
			name:            "Account API success",
			accountError:    nil,
			accountRegions:  []string{"us-east-1", "us-west-2"},
			expectedRegions: []string{"us-east-1", "us-west-2"},
		},
		{
			name:            "Account fails, EC2 succeeds",
			accountError:    fmt.Errorf("account error"),
			ec2Error:        nil,
			ec2Regions:      []string{"us-east-1", "eu-west-1"},
			expectedRegions: []string{"us-east-1", "eu-west-1"},
		},
		{
			name:            "Both fail, hardcoded fallback",
			accountError:    fmt.Errorf("account error"),
			ec2Error:        fmt.Errorf("ec2 error"),
			expectedRegions: Regions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccount := &mockAccountClient{
				listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
					if tt.accountError != nil {
						return nil, tt.accountError
					}
					var regions []awstypes.Region
					for _, r := range tt.accountRegions {
						rCopy := r
						regions = append(regions, awstypes.Region{RegionName: &rCopy})
					}
					return &account.ListRegionsOutput{Regions: regions}, nil
				},
			}

			mockEC2 := &mockEC2Client{
				describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
					if tt.ec2Error != nil {
						return nil, tt.ec2Error
					}
					var regions []ec2types.Region
					for _, r := range tt.ec2Regions {
						rCopy := r
						regions = append(regions, ec2types.Region{RegionName: &rCopy})
					}
					return &ec2.DescribeRegionsOutput{Regions: regions}, nil
				},
			}

			resolver := &RegionResolver{
				accountClient: mockAccount,
				ec2Client:     mockEC2,
			}

			regions, err := resolver.GetEnabledRegions(context.Background())

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedRegions, regions)
		})
	}
}

func TestEnabledRegions_EmptyProfile(t *testing.T) {
	// Test that EnabledRegions works with empty profile
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			usEast1 := "us-east-1"
			return &account.ListRegionsOutput{
				Regions: []awstypes.Region{
					{RegionName: &usEast1},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1"}, regions)
}

func TestEnabledRegions_IntegrationWithNewAWSConfig(t *testing.T) {
	// Test that EnabledRegions signature accepts profile and profileDir
	// This will be the public API
	before := regionsSnapshot()

	profile := "test-profile"
	profileDir := "/tmp/test-profiles"

	// Create a mock config
	mockCfg := aws.Config{
		Region: "us-east-1",
	}

	// Mock the config loader
	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()

	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return mockCfg, nil
	}

	// The mocked loader hands back a config carrying no credentials, so tier 1 and
	// tier 2 both fail and resolution lands on tier 3.
	regions, err := EnabledRegions(profile, profileDir)

	require.NoError(t, err, "a tier-3 fallback must degrade, not error")

	// Order-sensitive equality against the whole compiled-in list, not NotEmpty.
	// NotEmpty is satisfied by a single element, so a regression that truncated the
	// fallback — or swapped it for a plausible-looking default like {"us-east-1"} —
	// would pass here while silently cutting scan coverage to one region.
	assert.Equal(t, before, regions,
		"a tier-3 result must be exactly the compiled-in list, in its "+
			"compiled-in order")
	assert.Equal(t, before, Regions, "package Regions var must be unmutated")
}

// ---------------------------------------------------------------------------
// LAB-5615 / T007 — EnabledRegionsWithSource provenance (SAC-8, SAC-9)
// ---------------------------------------------------------------------------

// regionsSnapshot captures the package-level Regions var so a test can prove it
// was not mutated. Tier 3 returns that variable, so any caller that sorts the
// result in place would permanently reorder a process-global.
func regionsSnapshot() []string {
	return append([]string(nil), Regions...)
}

func succeedingAccountClient(regions ...string) *mockAccountClient {
	return &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			out := make([]awstypes.Region, 0, len(regions))
			for _, r := range regions {
				rCopy := r
				out = append(out, awstypes.Region{RegionName: &rCopy})
			}
			return &account.ListRegionsOutput{Regions: out}, nil
		},
	}
}

func failingAccountClient(err error) *mockAccountClient {
	return &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, err
		},
	}
}

func succeedingEC2Client(regions ...string) *mockEC2Client {
	return &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			out := make([]ec2types.Region, 0, len(regions))
			for _, r := range regions {
				rCopy := r
				out = append(out, ec2types.Region{RegionName: &rCopy})
			}
			return &ec2.DescribeRegionsOutput{Regions: out}, nil
		},
	}
}

func failingEC2Client(err error) *mockEC2Client {
	return &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			return nil, err
		},
	}
}

// SAC-8: each tier reports the provenance that actually produced the list.
func TestGetEnabledRegionsWithSource_ReportsTier(t *testing.T) {
	tests := []struct {
		name           string
		accountClient  AccountRegionLister
		ec2Client      EC2RegionLister
		expectedSource output.RegionSource
		expectRegions  []string
	}{
		{
			name:           "tier 1 succeeds",
			accountClient:  succeedingAccountClient("us-east-1", "us-west-2"),
			ec2Client:      succeedingEC2Client("should-not-be-used"),
			expectedSource: output.SourceAccountAPI,
			expectRegions:  []string{"us-east-1", "us-west-2"},
		},
		{
			name:           "tier 1 errors, tier 2 succeeds",
			accountClient:  failingAccountClient(fmt.Errorf("account API denied")),
			ec2Client:      succeedingEC2Client("us-east-1", "eu-west-1"),
			expectedSource: output.SourceEC2API,
			expectRegions:  []string{"us-east-1", "eu-west-1"},
		},
		{
			name:           "both error, static fallback",
			accountClient:  failingAccountClient(fmt.Errorf("account API denied")),
			ec2Client:      failingEC2Client(fmt.Errorf("ec2 API denied")),
			expectedSource: output.SourceStaticFallback,
			expectRegions:  Regions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := regionsSnapshot()

			resolver := &RegionResolver{
				accountClient: tt.accountClient,
				ec2Client:     tt.ec2Client,
			}

			// There is no error to check: getEnabledRegionsWithSource returns no
			// error at all, so "a fallback never surfaces as an error" is now
			// enforced by the signature rather than asserted case by case.
			regions, source := resolver.getEnabledRegionsWithSource(context.Background())

			assert.Equal(t, tt.expectedSource, source)
			assert.Equal(t, tt.expectRegions, regions)
			assert.Equal(t, before, Regions, "package Regions var must be unmutated")
		})
	}
}

// A nil account client must skip tier 1 rather than panic, matching
// GetEnabledRegions' existing nil-guard behaviour.
func TestGetEnabledRegionsWithSource_NilClientsSkipTiers(t *testing.T) {
	resolver := &RegionResolver{
		ec2Client: succeedingEC2Client("ap-south-1"),
	}

	regions, source := resolver.getEnabledRegionsWithSource(context.Background())

	assert.Equal(t, output.SourceEC2API, source)
	assert.Equal(t, []string{"ap-south-1"}, regions)
}

func TestGetEnabledRegionsWithSource_NoClientsFallsBackToStatic(t *testing.T) {
	resolver := &RegionResolver{}

	regions, source := resolver.getEnabledRegionsWithSource(context.Background())

	assert.Equal(t, output.SourceStaticFallback, source)
	assert.Equal(t, Regions, regions)
}

// SAC-9 / mutation hazard: the returned slice must not alias the package var.
//
// This is the regression test for the hazard. Delete the clone in
// getEnabledRegionsWithSource and this test fails.
func TestGetEnabledRegionsWithSource_StaticFallbackDoesNotAliasPackageVar(t *testing.T) {
	before := regionsSnapshot()

	resolver := &RegionResolver{
		accountClient: failingAccountClient(fmt.Errorf("boom")),
		ec2Client:     failingEC2Client(fmt.Errorf("boom")),
	}

	regions, source := resolver.getEnabledRegionsWithSource(context.Background())
	require.Equal(t, output.SourceStaticFallback, source)
	require.Equal(t, before, regions, "precondition: fallback returns the static list")

	// The caller sorts, as the Batch 3 coordinator will.
	sort.Strings(regions)

	assert.Equal(t, before, Regions,
		"sorting the returned slice must not reorder the package Regions var")

	// Sanity: sorting actually changed the local slice, so the assertion above
	// is meaningful rather than vacuously true.
	require.NotEqual(t, before, regions,
		"precondition: the static list is not already sorted, so sort() is observable")
}

// Writing through the returned slice must also not reach the package var.
func TestGetEnabledRegionsWithSource_ReturnedSliceIsWritable(t *testing.T) {
	before := regionsSnapshot()

	resolver := &RegionResolver{}
	regions, _ := resolver.getEnabledRegionsWithSource(context.Background())
	require.NotEmpty(t, regions)

	regions[0] = "MUTATED"

	assert.Equal(t, before, Regions, "package Regions var must be unmutated")
	assert.NotContains(t, Regions, "MUTATED")
}

// SAC-9 / F-4: a cancelled context must reach the SDK clients.
//
// The coordinator is the single point of failure for every downstream shard.
// With aws.RetryModeAdaptive an unreachable endpoint retries until the SDK
// budget is exhausted, so the context must be threaded all the way down rather
// than replaced with context.TODO().
func TestGetEnabledRegionsWithSource_PropagatesContextToClients(t *testing.T) {
	var (
		mu            sync.Mutex
		accountCtxErr error
		ec2CtxErr     error
		accountCalled bool
		ec2Called     bool
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the call

	resolver := &RegionResolver{
		accountClient: &mockAccountClient{
			listRegionsFunc: func(c context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
				mu.Lock()
				accountCalled, accountCtxErr = true, c.Err()
				mu.Unlock()
				return nil, c.Err()
			},
		},
		ec2Client: &mockEC2Client{
			describeRegionsFunc: func(c context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
				mu.Lock()
				ec2Called, ec2CtxErr = true, c.Err()
				mu.Unlock()
				return nil, c.Err()
			},
		},
	}

	_, source := resolver.getEnabledRegionsWithSource(ctx)
	// Scope note: this is a claim about getEnabledRegionsWithSource ALONE, which
	// has no error return at all — it reports provenance and nothing else, so a
	// cancelled context can only ever show up here as a tier-3 source. It is NOT
	// a claim about what the package does with a cancelled context. The two
	// exported entry points that have an error to return turn exactly this state
	// (static fallback reached under a done ctx) into one, each at its own
	// separate fmt.Errorf call site: EnabledRegionsWithSource, which wraps this
	// function, and GetEnabledRegions, which is not a wrapper of it at all — it
	// reaches the same state through resolveRegions, because this path's tier-3
	// Warn belongs to it alone. See
	// TestEnabledRegionsWithSource_CanceledContextIsAnError and
	// TestGetEnabledRegions_CanceledContextIsAnError.
	assert.Equal(t, output.SourceStaticFallback, source,
		"getEnabledRegionsWithSource has no error return, so a cancelled context "+
			"can only surface here as static-fallback provenance; the error is "+
			"added by the two exported entry points that have one to return "+
			"(EnabledRegionsWithSource, which wraps this function, and "+
			"GetEnabledRegions, which reaches the same state through "+
			"resolveRegions), not by this helper")

	mu.Lock()
	defer mu.Unlock()
	require.True(t, accountCalled, "tier 1 client must have been invoked")
	require.True(t, ec2Called, "tier 2 client must have been invoked")
	assert.ErrorIs(t, accountCtxErr, context.Canceled,
		"the cancelled ctx must reach the Account client, not context.TODO()")
	assert.ErrorIs(t, ec2CtxErr, context.Canceled,
		"the cancelled ctx must reach the EC2 client, not context.TODO()")
}

// SAC-8: the exported entry point threads its ctx and reports provenance.
//
// The context here is LIVE, and that is the whole point of this test. An
// unreachable control plane and an abandoned caller are the two categories the
// LAB-5615 guard exists to separate, and only the first one degrades: the
// mocked loader hands back a config carrying no credentials, so tier 1 and
// tier 2 both fail on their own merits while the caller is still waiting for an
// answer. That is a genuine unreachable-control-plane scenario, so
// "must degrade, not fail" is true here and assertable — EnabledRegionsWithSource
// has an error return to check it against.
//
// The cancelled-context counterpart is
// TestEnabledRegionsWithSource_CanceledContextIsAnError, which asserts the
// opposite outcome. Do not merge the two: sharing a fixture between them would
// re-conflate exactly the two categories the production guard distinguishes.
func TestEnabledRegionsWithSource_UnreachableTiersDegradeToStaticList(t *testing.T) {
	before := regionsSnapshot()

	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()
	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{Region: "us-east-1"}, nil
	}

	regions, source, err := EnabledRegionsWithSource(context.Background(), "test-profile", "/tmp/test-profiles")

	require.NoError(t, err, "an unreachable control plane must degrade, not fail")
	assert.Equal(t, output.SourceStaticFallback, source)

	// Order-sensitive equality against the whole compiled-in list, not NotEmpty.
	// Reporting static-fallback is a claim about WHICH list came back: a bug that
	// degraded to a truncated list — or to a plausible single-region default like
	// {"us-east-1"} — while still stamping static-fallback would satisfy NotEmpty
	// and ship silently reduced scan coverage under an authoritative-looking source.
	assert.Equal(t, before, regions,
		"a static-fallback result must be exactly the compiled-in list, in its "+
			"compiled-in order")
	assert.Equal(t, before, Regions, "package Regions var must be unmutated")

	// The caller owns the result and may sort it.
	sort.Strings(regions)
	assert.Equal(t, before, Regions, "sorting the result must not touch the package var")

	// Sanity: sorting actually reordered the local slice, so the assertion above
	// is meaningful rather than vacuously true. Without this, a compiled-in list
	// that happened to be sorted would make sort.Strings a no-op and the
	// sort-safety claim would hold for the wrong reason.
	require.NotEqual(t, before, regions,
		"precondition: the static list is not already sorted, so sort() is observable")
}

// The exported entry point must NOT report the compiled-in list as an answer
// when the caller has already abandoned the work.
//
// This is the other side of the line drawn above. A tier miss means the remote
// end could not be reached, and degrading is correct. A done context means the
// CALLER walked away: both SDK calls fail with that context error, the ladder
// reaches tier 3, and handing back the compiled-in list with a nil error would
// give an abandoned coordinator fabricated coverage to fan every downstream
// shard across.
//
// Both wrapped sentinels are pinned, not just one. errors.Is working here is
// bought entirely by the %w in the guard's fmt.Errorf; a future refactor to %v
// would still produce an error with an identical message, so require.Error and
// any Contains-style check on the text would both keep passing while errors.Is
// silently went false at every call site. Only ErrorIs catches that.
func TestEnabledRegionsWithSource_CanceledContextIsAnError(t *testing.T) {
	tests := []struct {
		name         string
		ctx          func(t *testing.T) context.Context
		wantSentinel error
	}{
		{
			name: "caller cancelled",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantSentinel: context.Canceled,
		},
		{
			name: "caller deadline already passed",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), -1*time.Second)
				t.Cleanup(cancel)
				return ctx
			},
			wantSentinel: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := regionsSnapshot()

			oldLoader := defaultConfigLoader
			defer func() { defaultConfigLoader = oldLoader }()
			defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
				return aws.Config{Region: "us-east-1"}, nil
			}

			ctx := tt.ctx(t)
			require.ErrorIs(t, ctx.Err(), tt.wantSentinel,
				"precondition: the context must already be done with the intended cause")

			regions, source, err := EnabledRegionsWithSource(ctx, "test-profile", "/tmp/test-profiles")

			require.Error(t, err,
				"a static-fallback result reached under a done context is fabricated "+
					"coverage, not an answer")
			assert.ErrorIs(t, err, tt.wantSentinel,
				"the guard must wrap ctx.Err() with %w so errors.Is keeps working at "+
					"the call site")
			assert.Nil(t, regions,
				"no region list may be handed back when none was actually fetched")
			assert.Empty(t, string(source),
				"no provenance may be claimed for a list the ladder never fetched")
			assert.Equal(t, before, Regions, "package Regions var must be unmutated")
		})
	}
}

// EnabledRegionsWithSource must surface config errors rather than silently
// falling back, because a config failure is a caller problem, not a tier miss.
func TestEnabledRegionsWithSource_PropagatesConfigError(t *testing.T) {
	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()
	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, fmt.Errorf("no credentials configured")
	}

	regions, source, err := EnabledRegionsWithSource(context.Background(), "p", "/tmp/d")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials configured")
	assert.Nil(t, regions)
	assert.Empty(t, string(source), "no source is claimed when resolution never ran")
}

// The legacy entry point must still fall through to the static list when both
// tiers fail.
//
// This test is deliberately NOT named "...Unmutated". It asserts value equality
// only, and value equality cannot see aliasing: these assertions pass identically
// whether GetEnabledRegions returns the package var or a copy of it. Nothing here
// writes through the returned slice, so no mutation claim is being made.
//
// The legacy path's CLONING behaviour is a separate contract, pinned by pointer
// identity in TestResolveRegions_TierThreeResultIsAlwaysCloned below.
//
// A write-through assertion would now be legitimate here: GetEnabledRegions
// clones at tier 3, so writing through the returned slice can no longer mutate
// the process-global Regions var. It is simply not this test's job — this test
// covers fall-through, and the clone is pinned by pointer identity below, which
// is a stronger check than mutation and does not disturb the package var.
func TestEnabledRegions_FallsBackToStaticList(t *testing.T) {
	before := regionsSnapshot()

	resolver := &RegionResolver{
		accountClient: failingAccountClient(fmt.Errorf("boom")),
		ec2Client:     failingEC2Client(fmt.Errorf("boom")),
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	require.NoError(t, err)
	assert.Equal(t, before, regions)
	assert.True(t, slices.Equal(before, Regions), "package Regions var must be unmutated")
}

// GetEnabledRegions carries the same cancellation guard as
// EnabledRegionsWithSource, and it is pinned here for the same reason: the %w
// wrap is what makes errors.Is work, and the two guards are separate
// fmt.Errorf call sites, so an assertion on one cannot catch a regression in
// the other.
//
// Honest scope note: this path is not reachable with a done context from any
// in-repo caller today. GetEnabledRegions is reached from EnabledRegions, which
// passes context.TODO(), and ResolveRegions likewise — both have an
// unconditionally nil Err(). The guard is pinned as defensive symmetry with the
// exported wrapper above, so that a future caller threading a real context gets
// the same contract rather than fabricated coverage, and so that the two guards
// cannot silently drift apart.
//
// The third row is a negative control and it is what gives the first two their
// meaning. Without it this test would pass just as happily against a guard
// written as `if ctx.Err() != nil` with no source check — a guard that would
// throw away real tier-1 data whenever the caller's context finished a moment
// after the SDK answered. The narrowness of the guard is a behaviour, and only a
// case where the context is done AND a tier succeeded can observe it.
func TestGetEnabledRegions_CanceledContextIsAnError(t *testing.T) {
	doneCtx := func(t *testing.T) context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	tests := []struct {
		name         string
		resolver     func() *RegionResolver
		ctx          func(t *testing.T) context.Context
		wantSentinel error // nil means the call must succeed
		wantRegions  []string
	}{
		{
			name: "cancelled caller reaching tier 3 is an error",
			resolver: func() *RegionResolver {
				return &RegionResolver{
					accountClient: failingAccountClient(fmt.Errorf("account API unreachable")),
					ec2Client:     failingEC2Client(fmt.Errorf("ec2 API unreachable")),
				}
			},
			ctx:          doneCtx,
			wantSentinel: context.Canceled,
		},
		{
			name: "expired deadline reaching tier 3 is an error",
			resolver: func() *RegionResolver {
				return &RegionResolver{
					accountClient: failingAccountClient(fmt.Errorf("account API unreachable")),
					ec2Client:     failingEC2Client(fmt.Errorf("ec2 API unreachable")),
				}
			},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), -1*time.Second)
				t.Cleanup(cancel)
				return ctx
			},
			wantSentinel: context.DeadlineExceeded,
		},
		{
			// Negative control: the guard is scoped to the fabricated case only.
			// Tier 1 answered, so this list is data the ladder really fetched and
			// it must be returned even though the context finished.
			name: "tier 1 success under a done ctx is still real data",
			resolver: func() *RegionResolver {
				return &RegionResolver{
					accountClient: succeedingAccountClient("us-east-1", "eu-west-1"),
					ec2Client:     failingEC2Client(fmt.Errorf("must not be consulted")),
				}
			},
			ctx:          doneCtx,
			wantSentinel: nil,
			wantRegions:  []string{"us-east-1", "eu-west-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := regionsSnapshot()

			ctx := tt.ctx(t)
			require.Error(t, ctx.Err(),
				"precondition: every row here runs under an already-done context")

			regions, err := tt.resolver().GetEnabledRegions(ctx)

			if tt.wantSentinel == nil {
				require.NoError(t, err,
					"a tier that actually answered must not be discarded just because "+
						"the caller's context finished afterwards")
				assert.Equal(t, tt.wantRegions, regions,
					"the fetched list must be returned unchanged")
			} else {
				require.Error(t, err,
					"a static-fallback result reached under a done context is fabricated "+
						"coverage, not an answer")
				assert.ErrorIs(t, err, tt.wantSentinel,
					"the guard must wrap ctx.Err() with %w so errors.Is keeps working at "+
						"the call site")
				assert.Nil(t, regions,
					"no region list may be handed back when none was actually fetched")
			}

			assert.Equal(t, before, Regions, "package Regions var must be unmutated")
		})
	}
}

// Both entry points share the resolveRegions ladder, and BOTH must hand the
// caller a clone at tier 3. Value equality cannot see that — the assertions
// above pass identically whether a function returns the package var or a copy of
// it. Only pointer identity can.
//
// resolveRegions itself still returns the package-level Regions variable ITSELF
// at tier 3; that is deliberate and unchanged (see its doc comment). The
// guarantee lives at the two entry points, each of which clones before handing
// the slice outward:
//
//   - GetEnabledRegions (legacy) returns slices.Clone of it.
//   - getEnabledRegionsWithSource (new) returns slices.Clone of it.
//
// Both halves are real guarantees, not frozen hazards: a caller entitled to sort
// its result must not be able to permanently reorder the process-global Regions
// var that AWSCommonRecon.PostBind reads on the live bind path. Do not weaken
// either assertion to value-equality — that would silently restore the aliasing
// the pointer check exists to exclude. Pointer identity is checked instead of
// mutating, so the package var is never disturbed.
func TestResolveRegions_TierThreeResultIsAlwaysCloned(t *testing.T) {
	before := regionsSnapshot()
	require.NotEmpty(t, Regions, "precondition: the static list is non-empty")

	newResolver := func() *RegionResolver {
		return &RegionResolver{
			accountClient: failingAccountClient(fmt.Errorf("boom")),
			ec2Client:     failingEC2Client(fmt.Errorf("boom")),
		}
	}

	legacy, err := newResolver().GetEnabledRegions(context.Background())
	require.NoError(t, err)
	require.Equal(t, before, legacy, "precondition: legacy fell through to tier 3")

	assert.NotSame(t, &Regions[0], &legacy[0],
		"GetEnabledRegions must return a CLONE at tier 3, so a caller that sorts "+
			"the result cannot reorder the process-global Regions var")

	cloned, source := newResolver().getEnabledRegionsWithSource(context.Background())
	require.Equal(t, output.SourceStaticFallback, source)
	require.Equal(t, before, cloned, "precondition: the new path fell through to tier 3")

	assert.NotSame(t, &Regions[0], &cloned[0],
		"getEnabledRegionsWithSource must return a clone, so a caller that sorts "+
			"the result cannot reorder the process-global Regions var")

	assert.Equal(t, before, Regions, "no assertion above may disturb the package var")
}

// ---------------------------------------------------------------------------
// Tier-3 Warn logging. The log record is BEHAVIOUR, not decoration.
// ---------------------------------------------------------------------------

// recordingHandler captures slog records so a test can assert what was logged and
// at which level. Enabled always reports true so the handler itself can never be
// the reason a record is missing: these assertions are about what the code under
// test emits, not about handler filtering.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// messagesAtLevel returns the messages recorded at exactly the given level.
func (h *recordingHandler) messagesAtLevel(lvl slog.Level) []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []string
	for _, r := range h.records {
		if r.Level == lvl {
			out = append(out, r.Message)
		}
	}
	return out
}

// TestGetEnabledRegionsWithSource_StaticFallbackLogsAtWarn pins the tier-3 log
// LEVEL, which is load-bearing rather than cosmetic.
//
// Demoting this record to Debug is a regression that no assertion on the RETURNED
// VALUE can catch: the regions and the source come back identical either way, so
// only an assertion on the record itself sees it. A silent drop to the compiled-in
// list is precisely the failure LAB-5615 exists to surface.
//
// Two facts make Warn the level that has to be pinned:
//
//   - Nothing selects the level at runtime. configureSlog (cmd/generator.go) is
//     reached from exactly one call site, which passes a string literal resolving
//     to slog.LevelWarn. There is no flag and no env var that raises verbosity, so
//     a Debug record on this path reaches no operator.
//   - SlogHandler.Enabled (pkg/plugin/log.go) returns true outright for Warn and
//     above, consulting its configured minimum only for levels below that. The
//     record therefore keeps passing even if that hardcoded level is later quieted
//     to "error".
//
// The tier-1 and tier-2 rows are negative controls. Without them this test would
// pass equally well against code that warned on every call, which trains operators
// to ignore the line and defeats the purpose as thoroughly as silence would. Both
// rows are needed because they are different branches of the ladder: a guard that
// is wrong for exactly one of them — say `source != output.SourceAccountAPI` —
// would satisfy the tier-1 row while warning spuriously on every EC2-API success.
func TestGetEnabledRegionsWithSource_StaticFallbackLogsAtWarn(t *testing.T) {
	tests := []struct {
		name       string
		resolver   func() *RegionResolver
		wantSource output.RegionSource
		wantWarn   bool
	}{
		{
			name:       "tier 3 fallback warns",
			resolver:   func() *RegionResolver { return &RegionResolver{} },
			wantSource: output.SourceStaticFallback,
			wantWarn:   true,
		},
		{
			name: "tier 1 success is silent at Warn",
			resolver: func() *RegionResolver {
				return &RegionResolver{accountClient: succeedingAccountClient("us-east-1")}
			},
			wantSource: output.SourceAccountAPI,
			wantWarn:   false,
		},
		{
			name: "tier 2 success is silent at Warn",
			resolver: func() *RegionResolver {
				return &RegionResolver{
					accountClient: failingAccountClient(fmt.Errorf("account API denied")),
					ec2Client:     succeedingEC2Client("us-east-1", "eu-west-1"),
				}
			},
			wantSource: output.SourceEC2API,
			wantWarn:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &recordingHandler{}
			restore := slog.Default()
			slog.SetDefault(slog.New(h))
			t.Cleanup(func() { slog.SetDefault(restore) })

			_, source := tt.resolver().getEnabledRegionsWithSource(context.Background())
			require.Equal(t, tt.wantSource, source,
				"precondition: the intended tier did not produce the list")

			warnings := h.messagesAtLevel(slog.LevelWarn)

			if !tt.wantWarn {
				assert.Empty(t, warnings,
					"a successful tier must not warn; an unconditional warning trains "+
						"operators to ignore the one case that matters")
				return
			}

			require.Len(t, warnings, 1, "tier 3 must emit exactly one Warn record")
			assert.Contains(t, warnings[0], "compiled-in region list",
				"the Warn record must name the fallback so an operator can act on it")
		})
	}
}
