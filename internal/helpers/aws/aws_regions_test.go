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
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

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
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

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
	assert.Equal(t, Regions, regions)
	assert.Greater(t, len(regions), 0, "hardcoded Regions list should not be empty")
}

func TestEnabledRegions_FullTieredFallback(t *testing.T) {
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
	before := regionsSnapshot()

	profile := "test-profile"
	profileDir := "/tmp/test-profiles"

	mockCfg := aws.Config{
		Region: "us-east-1",
	}

	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()

	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return mockCfg, nil
	}

	// The mocked loader hands back a config carrying no credentials, so tier 1 and
	// tier 2 both fail and resolution lands on tier 3.
	regions, err := EnabledRegions(profile, profileDir)

	require.NoError(t, err, "a tier-3 fallback must degrade, not error")

	// Equality against the whole list, not NotEmpty: NotEmpty is satisfied by a
	// single element, so a regression that truncated the fallback would pass here
	// while silently cutting scan coverage to one region.
	assert.Equal(t, before, regions,
		"a tier-3 result must be exactly the compiled-in list, in its "+
			"compiled-in order")
	assert.Equal(t, before, Regions, "package Regions var must be unmutated")
}

// regionsSnapshot captures the package-level Regions var so a test can prove it
// was not mutated: tier 3 returns that variable, so a caller sorting the result
// in place would permanently reorder a process-global.
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

			// No error to check: the signature has no error return, so "a fallback
			// never surfaces as an error" is enforced by the type, not asserted.
			regions, source := resolver.getEnabledRegionsWithSource(context.Background())

			assert.Equal(t, tt.expectedSource, source)
			assert.Equal(t, tt.expectRegions, regions)
			assert.Equal(t, before, Regions, "package Regions var must be unmutated")
		})
	}
}

// A nil client must skip its tier rather than panic.
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

// The returned slice must not alias the package var: delete the clone in
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

	sort.Strings(regions)

	assert.Equal(t, before, Regions,
		"sorting the returned slice must not reorder the package Regions var")

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

// A cancelled context must reach the SDK clients: under aws.RetryModeAdaptive an
// unreachable endpoint retries until the SDK budget is exhausted, so a
// context.TODO() here would leave an abandoned caller waiting out every retry.
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

// The context here is LIVE, and that is the point: tiers 1 and 2 fail on their
// own merits while the caller is still waiting, so degrading is correct.
//
// Do not merge this fixture with TestEnabledRegionsWithSource_CanceledContextIsAnError,
// which asserts the opposite outcome: sharing one would re-conflate the
// unreachable-control-plane and abandoned-caller cases the guard separates.
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

	// Equality against the whole list, not NotEmpty: a bug that degraded to a
	// truncated list while still stamping static-fallback would satisfy NotEmpty
	// and ship reduced coverage under an authoritative-looking source.
	assert.Equal(t, before, regions,
		"a static-fallback result must be exactly the compiled-in list, in its "+
			"compiled-in order")
	assert.Equal(t, before, Regions, "package Regions var must be unmutated")

	sort.Strings(regions)
	assert.Equal(t, before, Regions, "sorting the result must not touch the package var")

	require.NotEqual(t, before, regions,
		"precondition: the static list is not already sorted, so sort() is observable")
}

// The other side of that line: a done context means the CALLER walked away, so
// the compiled-in list with a nil error would hand an abandoned coordinator
// fabricated coverage to fan every downstream shard across.
//
// ErrorIs, not Contains: errors.Is works only because of the %w in the guard's
// fmt.Errorf, and a refactor to %v would leave the message identical — so a text
// check would stay green while errors.Is silently went false.
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

// A config failure is a caller problem, not a tier miss, so it must surface
// rather than degrade to the static list.
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

// Value equality only: these assertions pass identically whether the tier-3
// result aliases the package var or clones it. Aliasing is a separate contract,
// asserted by pointer identity in its own test.
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

// The two entry points' cancellation guards are separate fmt.Errorf call sites,
// so pinning one cannot catch a regression in the other. No in-repo caller
// reaches this one with a done context today; it is pinned as defensive symmetry
// so the two guards cannot silently drift apart.
//
// The third row is a negative control, and it is what gives the first two their
// meaning: without it this test would pass equally against a guard written as
// `if ctx.Err() != nil` with no source check — one that would throw away real
// tier-1 data whenever the caller's context finished just after the SDK answered.
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
			// Negative control: tier 1 answered, so this is data the ladder really
			// fetched and it must be returned even though the context finished.
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

// Both entry points must hand the caller a clone at tier 3, and value equality
// cannot see that — only pointer identity can. Do not weaken either NotSame to
// value equality: that would silently restore the aliasing the pointer check
// exists to exclude, letting a caller who sorts its result permanently reorder
// the process-global Regions var.
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

// recordingHandler captures slog records so a test can assert what was logged
// and at which level. Enabled always reports true so the handler can never
// itself be the reason a record is missing.
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

// recordsAtLevel returns the records captured at exactly the given level.
//
// Records are cloned on the way out: a slog.Record's attributes live partly in a
// backing array shared with the value the handler was given, so handing the
// stored record out directly would let a caller's Attrs iteration alias state the
// handler still owns.
func (h *recordingHandler) recordsAtLevel(lvl slog.Level) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []slog.Record
	for _, r := range h.records {
		if r.Level == lvl {
			out = append(out, r.Clone())
		}
	}
	return out
}

// messagesAtLevel returns the messages recorded at exactly the given level.
func (h *recordingHandler) messagesAtLevel(lvl slog.Level) []string {
	var out []string
	for _, r := range h.recordsAtLevel(lvl) {
		out = append(out, r.Message)
	}
	return out
}

// attrsOf flattens a record's attributes into a map so an assertion can name the
// key it cares about rather than depend on the order they were passed in.
func attrsOf(r slog.Record) map[string]slog.Value {
	out := make(map[string]slog.Value, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value
		return true
	})
	return out
}

// captureLogs routes the default logger into a recordingHandler for the test.
// The previous logger is captured BEFORE SetDefault, not reconstructed after, so
// a test that runs after another capture still restores the right one.
//
// Callers must not call t.Parallel(): this swaps the process-global default slog
// logger, so parallel callers would capture each other's records and restore the
// wrong logger on cleanup.
func captureLogs(t *testing.T) *recordingHandler {
	t.Helper()

	h := &recordingHandler{}
	restore := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(restore) })
	return h
}

// The tier-3 log LEVEL is load-bearing, not cosmetic. Demoting this record to
// Debug is a regression no assertion on the returned value can catch — the
// regions and the source come back identical either way — and nothing raises
// verbosity at runtime, so a Debug record on this path reaches no operator.
//
// The tier-1 and tier-2 rows are negative controls, and both are needed: a guard
// wrong for exactly one of them — say `source != output.SourceAccountAPI` — would
// satisfy the tier-1 row while warning spuriously on every EC2-API success.
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
			h := captureLogs(t)

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

// Pins the tier-3 Warn on the LEGACY entry point: GetEnabledRegions calls
// resolveRegions directly rather than routing through getEnabledRegionsWithSource,
// and it carries most of production — AWSCommonRecon.PostBind and the CDK scan
// path both reach the ladder only here, via helpers.EnabledRegions. That is the
// reported regression: with the Warn on the other function, both entry points
// fell back to the compiled-in list in silence.
//
// The tier-1 and tier-2 rows are negative controls, and both are needed: a warn
// guarded by `source != output.SourceAccountAPI` satisfies the tier-1 row while
// warning on every EC2-API success.
func TestGetEnabledRegions_StaticFallbackLogsAtWarn(t *testing.T) {
	tests := []struct {
		name        string
		resolver    func() *RegionResolver
		wantRegions []string
		wantWarn    bool
	}{
		{
			name:        "tier 3 fallback warns",
			resolver:    func() *RegionResolver { return &RegionResolver{} },
			wantRegions: Regions,
			wantWarn:    true,
		},
		{
			name: "tier 1 success is silent at Warn",
			resolver: func() *RegionResolver {
				return &RegionResolver{accountClient: succeedingAccountClient("us-east-1")}
			},
			wantRegions: []string{"us-east-1"},
			wantWarn:    false,
		},
		{
			name: "tier 2 success is silent at Warn",
			resolver: func() *RegionResolver {
				return &RegionResolver{
					accountClient: failingAccountClient(fmt.Errorf("account API denied")),
					ec2Client:     succeedingEC2Client("us-east-1", "eu-west-1"),
				}
			},
			wantRegions: []string{"us-east-1", "eu-west-1"},
			wantWarn:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := captureLogs(t)

			// The context is LIVE: the gate on the Warn is ctx.Err() == nil, so a
			// done context would suppress the record for a reason unrelated to the tier.
			regions, err := tt.resolver().GetEnabledRegions(context.Background())

			// GetEnabledRegions reports no provenance, so the returned list is the
			// only evidence available that the intended tier is the one that ran.
			require.NoError(t, err, "precondition: a live-context resolution must not error")
			require.Equal(t, tt.wantRegions, regions,
				"precondition: the intended tier did not produce the list")

			warns := h.recordsAtLevel(slog.LevelWarn)

			if !tt.wantWarn {
				assert.Empty(t, warns,
					"a tier that actually answered must not warn on this entry point; "+
						"a warning here describes coverage loss that did not happen")
				return
			}

			require.Len(t, warns, 1,
				"the legacy entry point must emit exactly one Warn when it falls back "+
					"to the compiled-in list")
			assert.Contains(t, warns[0].Message, "compiled-in region list",
				"the Warn must name the fallback so an operator can act on it")

			// Attributes are asserted only here, and once is enough — not by
			// assumption: resolveRegions holds the only slog.Warn call site in this
			// file, so there is no second record that could drift from this one.
			attrs := attrsOf(warns[0])

			source, ok := attrs["source"]
			require.True(t, ok, "the Warn must carry a source attribute")
			assert.Equal(t, string(output.SourceStaticFallback), source.String(),
				"the Warn must name the provenance it is warning about, so an operator "+
					"reading the log can tell this record apart from a tier that answered")

			count, ok := attrs["region_count"]
			require.True(t, ok, "the Warn must carry a region_count attribute")
			assert.Equal(t, int64(len(regions)), count.Int64(),
				"region_count must describe the list the caller actually received; a "+
					"count that disagrees with it would misreport the scan's breadth")
		})
	}
}

// The tier-3 Warn must be suppressed when the caller has already abandoned the
// work — the half of that behaviour no returned value can show. Nothing is
// scanned, so a record reading "scan coverage may omit regions" would be a false
// alarm on a call that already failed loudly. Alone this test is satisfied by an
// implementation that never warns at all, which is what makes the tier-3 row in
// the test above its complement rather than an overlap.
//
// The error assertions are PRECONDITIONS, not the claim — they establish that the
// row really reached the abandoned-caller path; the claim is the ABSENCE of the
// record. Both causes are covered because the gate is ctx.Err() == nil, which is
// cause-blind: a gate narrowed to !errors.Is(ctx.Err(), context.Canceled) would
// still suppress for a cancelled caller, and only the deadline row would fail.
func TestGetEnabledRegions_DoneContextSuppressesTierThreeWarn(t *testing.T) {
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
			h := captureLogs(t)

			ctx := tt.ctx(t)
			require.ErrorIs(t, ctx.Err(), tt.wantSentinel,
				"precondition: the context must already be done with the intended cause")

			resolver := &RegionResolver{
				accountClient: failingAccountClient(fmt.Errorf("account API unreachable")),
				ec2Client:     failingEC2Client(fmt.Errorf("ec2 API unreachable")),
			}

			regions, err := resolver.GetEnabledRegions(ctx)

			require.Error(t, err,
				"precondition: this row must reach the abandoned-caller path, where the "+
					"static fallback is reported as an error rather than an answer")
			require.ErrorIs(t, err, tt.wantSentinel,
				"precondition: the error must be the one caused by this row's context")
			require.Nil(t, regions,
				"precondition: no list is handed back on the abandoned-caller path")

			assert.Empty(t, h.recordsAtLevel(slog.LevelWarn),
				"no Warn may be emitted when the caller has abandoned the work; the "+
					"record claims scan coverage may be reduced, and this call scans "+
					"nothing at all")
		})
	}
}
