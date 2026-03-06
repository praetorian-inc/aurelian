package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultToRisk(t *testing.T) {
	result := templates.ARGQueryResult{
		TemplateID: "storage_accounts_public_access",
		TemplateDetails: &templates.ARGQueryTemplate{
			ID:       "storage_accounts_public_access",
			Name:     "Publicly Accessible Storage Accounts",
			Severity: output.RiskSeverityHigh,
		},
		ResourceID:     "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage",
		ResourceName:   "mystorage",
		ResourceType:   "Microsoft.Storage/storageAccounts",
		SubscriptionID: "xxx",
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := resultToRisk(result, out)
		require.NoError(t, err)
	}()

	var risks []output.AurelianRisk
	for m := range out.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, out.Wait())
	require.Len(t, risks, 1)

	risk := risks[0]
	assert.Equal(t, "public-azure-resource", risk.Name)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Contains(t, risk.ImpactedARN, "mystorage")

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Equal(t, "storage_accounts_public_access", ctx["templateId"])
}

func TestEnrichResultSuppression(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()
	defer plugin.ResetAzureEnricherRegistry()

	// Register an enricher that suppresses the result.
	plugin.RegisterAzureEnricher("test_suppress", func(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
		result.Suppressed = true
		result.SuppressReason = "resource not actually public"
		return nil, nil
	})

	cfg := plugin.AzureEnricherConfig{}
	fn := enrichResult(cfg)

	result := templates.ARGQueryResult{
		TemplateID:   "test_suppress",
		ResourceID:   "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Test/resource1",
		ResourceName: "resource1",
	}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, fn(result, out))
	}()

	var results []templates.ARGQueryResult
	for r := range out.Range() {
		results = append(results, r)
	}
	require.NoError(t, out.Wait())
	assert.Empty(t, results, "suppressed result should not be emitted")
}

func TestEnrichResultNoSuppression(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()
	defer plugin.ResetAzureEnricherRegistry()

	// Register an enricher that does NOT suppress.
	plugin.RegisterAzureEnricher("test_pass", func(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
		return []plugin.AzureEnrichmentCommand{{Command: "curl test", Description: "test"}}, nil
	})

	cfg := plugin.AzureEnricherConfig{}
	fn := enrichResult(cfg)

	result := templates.ARGQueryResult{
		TemplateID:   "test_pass",
		ResourceID:   "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Test/resource2",
		ResourceName: "resource2",
	}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, fn(result, out))
	}()

	var results []templates.ARGQueryResult
	for r := range out.Range() {
		results = append(results, r)
	}
	require.NoError(t, out.Wait())
	require.Len(t, results, 1, "non-suppressed result should be emitted")
	assert.Equal(t, "resource2", results[0].ResourceName)
}

func TestModuleMetadata(t *testing.T) {
	m := &AzurePublicResourcesModule{}
	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, "Azure Public Resources", m.Name())
	assert.Equal(t, plugin.PlatformAzure, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.SupportedResourceTypes())
	assert.NotNil(t, m.Parameters())
}
