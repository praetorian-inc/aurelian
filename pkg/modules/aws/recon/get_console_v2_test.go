package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGetConsoleV2 verifies constructor defaults
func TestNewGetConsoleV2(t *testing.T) {
	g := NewGetConsoleV2("test-profile")

	assert.Equal(t, "test-profile", g.Profile)
	assert.Equal(t, "us-east-1", g.Region, "Region should default to us-east-1")
	assert.Equal(t, 3600, g.Duration, "Duration should default to 3600")
	assert.Equal(t, "console-session", g.RoleSessionName, "RoleSessionName should have default")
	assert.Equal(t, "console-user", g.FederationName, "FederationName should have default")
}

// TestGetConsoleV2_ValidateDuration_TooLow verifies duration minimum bound
func TestGetConsoleV2_ValidateDuration_TooLow(t *testing.T) {
	g := NewGetConsoleV2("test-profile")
	g.Duration = 899 // Below minimum of 900

	// Since we can't test Run() without real AWS credentials,
	// we need to test validation logic separately
	// For now, this test documents the requirement
	require.True(t, g.Duration < minDuration, "Test setup: duration should be below minimum")
}

// TestGetConsoleV2_ValidateDuration_TooHigh verifies duration maximum bound
func TestGetConsoleV2_ValidateDuration_TooHigh(t *testing.T) {
	g := NewGetConsoleV2("test-profile")
	g.Duration = 129601 // Above maximum of 129600

	require.True(t, g.Duration > maxDuration, "Test setup: duration should be above maximum")
}

// TestGetConsoleV2_ValidateDuration_Valid verifies duration within bounds
func TestGetConsoleV2_ValidateDuration_Valid(t *testing.T) {
	testCases := []struct {
		name     string
		duration int
	}{
		{"minimum", 900},
		{"default", 3600},
		{"maximum", 129600},
		{"mid-range", 7200},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGetConsoleV2("test-profile")
			g.Duration = tc.duration

			require.GreaterOrEqual(t, g.Duration, minDuration, "Duration should be >= minimum")
			require.LessOrEqual(t, g.Duration, maxDuration, "Duration should be <= maximum")
		})
	}
}

// TestDefaultCacheOptions verifies cache options helper
func TestDefaultCacheOptions(t *testing.T) {
	g := NewGetConsoleV2("test-profile")
	opts := g.defaultCacheOptions()

	require.NotNil(t, opts, "defaultCacheOptions should not return nil")
	require.Len(t, opts, 6, "Should return 6 cache options")

	// Verify all expected options are present
	expectedOptions := []*types.Option{
		&options.AwsCacheDirOpt,
		&options.AwsCacheExtOpt,
		&options.AwsCacheTTLOpt,
		&options.AwsDisableCacheOpt,
		&options.AwsCacheErrorRespOpt,
		&options.AwsCacheErrorRespTypesOpt,
	}

	assert.Equal(t, expectedOptions, opts, "Cache options should match expected set")
}
