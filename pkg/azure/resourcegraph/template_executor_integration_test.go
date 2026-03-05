//go:build integration

package resourcegraph

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	azure "github.com/praetorian-inc/aurelian/pkg/templates/azure"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateExecutor(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	subscriptionID := fixture.Output("subscription_id")
	sub := azuretypes.SubscriptionInfo{ID: subscriptionID}

	loader, err := azure.NewLoader()
	require.NoError(t, err)

	templatesByID := make(map[string]*templates.ARGQueryTemplate)
	for _, tmpl := range loader.GetTemplates() {
		templatesByID[tmpl.ID] = tmpl
	}

	t.Run("storage_accounts_public_access", func(t *testing.T) {
		tmpl, ok := templatesByID["storage_accounts_public_access"]
		require.True(t, ok, "template not found")

		results := executeTemplate(t, cred, tmpl, sub)
		require.NotEmpty(t, results, "expected at least one result")

		expectedID := fixture.Output("storage_account_id")
		assertResultContainsResource(t, results, expectedID, "storage_accounts_public_access", subscriptionID)
	})

	t.Run("sql_servers_public_access", func(t *testing.T) {
		tmpl, ok := templatesByID["sql_servers_public_access"]
		require.True(t, ok, "template not found")

		results := executeTemplate(t, cred, tmpl, sub)
		require.NotEmpty(t, results, "expected at least one result")

		expectedID := fixture.Output("sql_server_id")
		assertResultContainsResource(t, results, expectedID, "sql_servers_public_access", subscriptionID)
	})

	t.Run("key_vault_public_access", func(t *testing.T) {
		tmpl, ok := templatesByID["key_vault_public_access"]
		require.True(t, ok, "template not found")

		results := executeTemplate(t, cred, tmpl, sub)
		require.NotEmpty(t, results, "expected at least one result")

		expectedID := fixture.Output("key_vault_id")
		assertResultContainsResource(t, results, expectedID, "key_vault_public_access", subscriptionID)
	})
}

func executeTemplate(t *testing.T, cred *azidentity.DefaultAzureCredential, tmpl *templates.ARGQueryTemplate, sub azuretypes.SubscriptionInfo) []templates.ARGQueryResult {
	t.Helper()

	executor := NewTemplateExecutor(cred, tmpl)
	out := pipeline.New[templates.ARGQueryResult]()

	go func() {
		defer out.Close()
		err := executor.Execute(sub, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	return results
}

func assertResultContainsResource(t *testing.T, results []templates.ARGQueryResult, expectedResourceID, expectedTemplateID, expectedSubscriptionID string) {
	t.Helper()

	for _, r := range results {
		if !strings.EqualFold(r.ResourceID, expectedResourceID) {
			continue
		}

		assert.Equal(t, expectedTemplateID, r.TemplateID)
		assert.NotEmpty(t, r.ResourceType)
		assert.Equal(t, expectedSubscriptionID, r.SubscriptionID)
		t.Logf("found result: template=%s resource=%s type=%s", r.TemplateID, r.ResourceID, r.ResourceType)
		return
	}

	t.Errorf("expected result with resourceId=%q (checked %d results)", expectedResourceID, len(results))
}
