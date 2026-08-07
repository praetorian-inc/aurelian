package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"testing"

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
	tests := []struct {
		name             string
		accountError     error
		accountRegions   []string
		ec2Error         error
		ec2Regions       []string
		expectedRegions  []string
		expectedFallback string
	}{
		{
			name:             "Account API success",
			accountError:     nil,
			accountRegions:   []string{"us-east-1", "us-west-2"},
			expectedRegions:  []string{"us-east-1", "us-west-2"},
			expectedFallback: "account",
		},
		{
			name:             "Account fails, EC2 succeeds",
			accountError:     fmt.Errorf("account error"),
			ec2Error:         nil,
			ec2Regions:       []string{"us-east-1", "eu-west-1"},
			expectedRegions:  []string{"us-east-1", "eu-west-1"},
			expectedFallback: "ec2",
		},
		{
			name:             "Both fail, hardcoded fallback",
			accountError:     fmt.Errorf("account error"),
			ec2Error:         fmt.Errorf("ec2 error"),
			expectedRegions:  Regions,
			expectedFallback: "hardcoded",
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

	// This should compile and work with the new signature
	regions, err := EnabledRegions(profile, profileDir)

	// We expect it to fallback to hardcoded list since we don't have real AWS clients
	assert.NoError(t, err)
	assert.NotEmpty(t, regions)
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
	assert.Equal(t, output.SourceStaticFallback, source,
		"a cancelled context degrades to the static list, it does not error")

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
func TestEnabledRegionsWithSource_ReturnsSourceAndRegions(t *testing.T) {
	before := regionsSnapshot()

	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()
	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{Region: "us-east-1"}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	regions, source, err := EnabledRegionsWithSource(ctx, "test-profile", "/tmp/test-profiles")

	require.NoError(t, err, "an unreachable control plane must degrade, not fail")
	assert.NotEmpty(t, regions)
	assert.Equal(t, output.SourceStaticFallback, source)
	assert.Equal(t, before, Regions, "package Regions var must be unmutated")

	// The caller owns the result and may sort it.
	sort.Strings(regions)
	assert.Equal(t, before, Regions, "sorting the result must not touch the package var")
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
// The shipped binary hardcodes configureSlog("none") (cmd/generator.go), which maps
// to slog.LevelWarn, and SlogHandler.Enabled is level >= minLevel — so every Debug
// line on this path is discarded at every user-selectable setting. A silent
// fallback to the compiled-in list is the exact failure LAB-5615 exists to surface,
// so emitting this record at Debug would hide it from every operator. Demoting the
// level is a real regression that no assertion on the RETURNED VALUE can detect,
// because the regions and the source are identical either way.
//
// The tier-1 subtest is the negative control. Without it this test would pass just
// as well against code that warned unconditionally — which would train operators to
// ignore the line, defeating the purpose as surely as silence would.
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
