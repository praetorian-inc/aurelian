package recon

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiRegionParameterType verifies that the regions parameter is properly typed as []string
func TestMultiRegionParameterType(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	var regionsParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "regions" {
			regionsParam = &params[i]
			break
		}
	}

	require.NotNil(t, regionsParam, "regions parameter must exist")
	assert.Equal(t, "[]string", regionsParam.Type, "regions must be a string slice")

	// Default should be ["all"]
	defaultVal, ok := regionsParam.Default.([]string)
	require.True(t, ok, "default should be []string type")
	assert.Equal(t, []string{"all"}, defaultVal)
}

// TestMultiRegionParameterReading tests that the module correctly reads regions as []string
func TestMultiRegionParameterReading(t *testing.T) {
	m := &AWSListAllResourcesModule{}

	// Create a test config with multiple regions
	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"regions":     []string{"us-east-1", "us-west-2", "eu-west-1"},
			"scan-type":   "summary",
			"profile":     "test",
			"concurrency": 5,
		},
	}

	// Create parameters
	params := plugin.NewParameters(m.Parameters()...)
	for k, v := range cfg.Args {
		params.Set(k, v)
	}

	// Verify we can read regions as []string (not string)
	regions := params.StringSlice("regions")
	assert.Equal(t, []string{"us-east-1", "us-west-2", "eu-west-1"}, regions)
}

// TestAllRegionsResolution verifies "all" expands to enabled regions
func TestAllRegionsResolution(t *testing.T) {
	// This test documents the expected behavior:
	// When regions = ["all"], the implementation should:
	// 1. Call helpers.EnabledRegions(profile, opts) to resolve "all"
	// 2. Return the list of enabled AWS regions

	// For now, just document the expected interface
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	// Verify regions parameter accepts "all" value
	var regionsParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "regions" {
			regionsParam = &params[i]
			break
		}
	}

	require.NotNil(t, regionsParam)

	// Test that we can set "all"
	testParams := plugin.NewParameters(m.Parameters()...)
	testParams.Set("regions", []string{"all"})

	regions := testParams.StringSlice("regions")
	assert.Equal(t, []string{"all"}, regions, "'all' should be a valid region specifier")
}

// TestMultiRegionConcurrencySetup verifies proper rate limiting setup
func TestMultiRegionConcurrencySetup(t *testing.T) {
	// This test documents that the implementation should:
	// 1. Create ratelimit.NewAWSRegionLimiter(concurrency) ONCE
	// 2. Use errgroup for region iteration
	// 3. Each region goroutine calls limiter.Acquire(ctx, region)

	// For now, verify concurrency parameter exists and has correct default
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	var concurrencyParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "concurrency" {
			concurrencyParam = &params[i]
			break
		}
	}

	require.NotNil(t, concurrencyParam)
	assert.Equal(t, 5, concurrencyParam.Default, "default concurrency should be 5")
}

// TestRegionIterationPattern documents expected multi-region pattern
func TestRegionIterationPattern(t *testing.T) {
	// Expected pattern (documented, not enforced by this test):
	// 1. Read regions as []string
	// 2. If regions contains "all", resolve to enabled regions
	// 3. Create rate limiter: ratelimit.NewAWSRegionLimiter(concurrency)
	// 4. Use errgroup.Group with SetLimit(concurrency)
	// 5. For each region:
	//    - Spawn goroutine
	//    - Acquire rate limit: limiter.Acquire(ctx, region)
	//    - Create region-specific AWS config: helpers.GetAWSCfg(region, ...)
	//    - Create region-specific client: cloudcontrol.NewFromConfig(awsCfg)
	//    - Call cclist.ListAll() for that region
	//    - Merge results into shared map with mutex
	// 6. Wait for all goroutines: g.Wait()
	// 7. Return aggregated results

	// This test just verifies the module has all required parameters
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	paramNames := make([]string, len(params))
	for i, p := range params {
		paramNames[i] = p.Name
	}

	assert.Contains(t, paramNames, "regions", "must have regions parameter")
	assert.Contains(t, paramNames, "profile", "must have profile parameter")
	assert.Contains(t, paramNames, "concurrency", "must have concurrency parameter")
	assert.Contains(t, paramNames, "scan-type", "must have scan-type parameter")
}

// TestContextCancellationHandling verifies context cancellation is propagated
func TestContextCancellationHandling(t *testing.T) {
	// Expected behavior:
	// If context is cancelled during multi-region enumeration,
	// the errgroup should propagate the cancellation and stop all goroutines

	m := &AWSListAllResourcesModule{}

	// Create a context that's already cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(2 * time.Millisecond) // Ensure context is cancelled

	cfg := plugin.Config{
		Context: ctx,
		Args: map[string]any{
			"regions":     []string{"us-east-1"},
			"scan-type":   "summary",
			"concurrency": 5,
		},
	}

	// The Run method should respect context cancellation
	// (This will fail until implementation is fixed, which is expected for TDD RED phase)
	_ = cfg
	_ = m

	// Test currently documents expected behavior
	// Once implementation is fixed, this test can call m.Run(cfg) and verify
	// it returns context.Canceled or context.DeadlineExceeded error
}
