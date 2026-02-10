// +build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

// TestListAllResources_ActuallyReadsRegionsAsSlice is an integration test
// that will fail with the current broken code because it tries to read
// regions as String() instead of StringSlice()
func TestListAllResources_ActuallyReadsRegionsAsSlice(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	m := &AWSListAllResourcesModule{}

	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"regions":     []string{"us-east-1", "us-west-2"},
			"scan-type":   "summary",
			"profile":     "default",
			"concurrency": 2,
		},
	}

	// This will panic or fail in the current broken code at line 73
	// because it tries params.String("region") on a []string parameter
	results, err := m.Run(cfg)

	// With the fix, this should not error out on parameter reading
	// (it may error on AWS API calls if credentials aren't configured, which is fine)
	if err != nil {
		assert.NotContains(t, err.Error(), "parameter validation failed",
			"Should not fail on parameter validation after fix")
		assert.NotContains(t, err.Error(), "type assertion",
			"Should not fail on type assertion after fix")
	}

	_ = results
}
