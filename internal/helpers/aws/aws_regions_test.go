package helpers

import (
	"context"
	"fmt"
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

			regions, source, err := resolver.getEnabledRegionsWithSource(context.Background())

			require.NoError(t, err, "fallback must never surface as an error")
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

	regions, source, err := resolver.getEnabledRegionsWithSource(context.Background())

	require.NoError(t, err)
	assert.Equal(t, output.SourceEC2API, source)
	assert.Equal(t, []string{"ap-south-1"}, regions)
}

func TestGetEnabledRegionsWithSource_NoClientsFallsBackToStatic(t *testing.T) {
	resolver := &RegionResolver{}

	regions, source, err := resolver.getEnabledRegionsWithSource(context.Background())

	require.NoError(t, err)
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

	regions, source, err := resolver.getEnabledRegionsWithSource(context.Background())
	require.NoError(t, err)
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
	regions, _, err := resolver.getEnabledRegionsWithSource(context.Background())
	require.NoError(t, err)
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

	_, source, err := resolver.getEnabledRegionsWithSource(ctx)
	require.NoError(t, err)
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

// A cancelled context must return promptly rather than exhausting SDK retries.
func TestGetEnabledRegionsWithSource_CancelledContextReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	blockUnlessCancelled := func(c context.Context) error {
		select {
		case <-c.Done():
			return c.Err()
		case <-time.After(30 * time.Second):
			return fmt.Errorf("client ignored context cancellation")
		}
	}

	resolver := &RegionResolver{
		accountClient: &mockAccountClient{
			listRegionsFunc: func(c context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
				return nil, blockUnlessCancelled(c)
			},
		},
		ec2Client: &mockEC2Client{
			describeRegionsFunc: func(c context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
				return nil, blockUnlessCancelled(c)
			},
		},
	}

	done := make(chan struct{})
	var source output.RegionSource
	var err error

	start := time.Now()
	go func() {
		defer close(done)
		_, source, err = resolver.getEnabledRegionsWithSource(ctx)
	}()

	select {
	case <-done:
		assert.Less(t, time.Since(start), 5*time.Second,
			"cancelled context must short-circuit, not exhaust the retry budget")
		require.NoError(t, err)
		assert.Equal(t, output.SourceStaticFallback, source)
	case <-time.After(5 * time.Second):
		require.Fail(t, "getEnabledRegionsWithSource did not return promptly on a cancelled context")
	}
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

// The legacy entry point must keep behaving exactly as before this change.
func TestEnabledRegions_StillReturnsStaticListUnmutated(t *testing.T) {
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
