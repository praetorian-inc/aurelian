//go:build integration

package recon

import (
	"context"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestAWSListAllEC2Enumeration(t *testing.T) {
	// Step 1: Create fixture and provision infrastructure
	fixture := testutil.NewFixture(t, "aws/list")
	fixture.Setup()

	// Step 2: Retrieve module from registry
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Skip("list-all module not registered in plugin system")
	}

	// Step 3: Execute module against provisioned resources
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::EC2::Instance"},
			"regions":       []string{"us-east-2"},
			"scan-type":     "full",
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Step 4: Assert results contain expected resources
	testutil.AssertMinResults(t, results, 1)

	// Verify each provisioned instance ID is found in results
	for _, id := range fixture.OutputList("instance_ids") {
		testutil.AssertResultContainsString(t, results, id)
	}
}
