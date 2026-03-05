//go:build integration

package extraction

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureExtractor(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err, "failed to create Azure credential")

	subscriptionID := fixture.Output("subscription_id")
	extractor := NewAzureExtractor(cred)

	t.Run("extracts VM user data", func(t *testing.T) {
		vmID := fixture.Output("vm_id")
		resource := output.AzureResource{
			ResourceID:     vmID,
			ResourceType:   "Microsoft.Compute/virtualMachines",
			SubscriptionID: subscriptionID,
		}

		results := collectScanInputs(t, extractor, resource)
		require.NotEmpty(t, results, "expected scan inputs from VM")

		found := scanInputsContain(results, "AKIAIOSFODNN7EXAMPLE")
		assert.True(t, found, "expected VM user data to contain fake AWS key")
	})

	t.Run("extracts web app settings", func(t *testing.T) {
		webAppID := fixture.Output("web_app_id")
		resource := output.AzureResource{
			ResourceID:     webAppID,
			ResourceType:   "Microsoft.Web/sites",
			SubscriptionID: subscriptionID,
		}

		results := collectScanInputs(t, extractor, resource)
		require.NotEmpty(t, results, "expected scan inputs from web app")

		found := scanInputsContain(results, "AKIAIOSFODNN7EXAMPLE")
		assert.True(t, found, "expected web app settings to contain fake AWS key")
	})

	t.Run("extracts automation variables", func(t *testing.T) {
		automationID := fixture.Output("automation_account_id")
		resource := output.AzureResource{
			ResourceID:     automationID,
			ResourceType:   "Microsoft.Automation/automationAccounts",
			SubscriptionID: subscriptionID,
		}

		results := collectScanInputs(t, extractor, resource)
		require.NotEmpty(t, results, "expected scan inputs from automation account")

		found := scanInputsContain(results, "wJalrXUtnFEMI")
		assert.True(t, found, "expected automation variable to contain fake AWS secret")
	})

	t.Run("extracts storage blobs", func(t *testing.T) {
		storageID := fixture.Output("storage_account_id")
		resource := output.AzureResource{
			ResourceID:     storageID,
			ResourceType:   "Microsoft.Storage/storageAccounts",
			SubscriptionID: subscriptionID,
		}

		results := collectScanInputs(t, extractor, resource)
		require.NotEmpty(t, results, "expected scan inputs from storage account")

		found := scanInputsContain(results, "AKIAIOSFODNN7EXAMPLE")
		assert.True(t, found, "expected storage blob to contain fake AWS key")
	})
}

func collectScanInputs(t *testing.T, extractor *AzureExtractor, resource output.AzureResource) []output.ScanInput {
	t.Helper()

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		err := extractor.Extract(resource, out)
		if err != nil {
			t.Logf("extraction error (may be expected): %v", err)
		}
	}()

	var results []output.ScanInput
	for si := range out.Range() {
		results = append(results, si)
	}
	return results
}

func scanInputsContain(inputs []output.ScanInput, substr string) bool {
	for _, si := range inputs {
		if strings.Contains(string(si.Content), substr) {
			return true
		}
	}
	return false
}
