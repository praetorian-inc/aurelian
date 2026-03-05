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
	assert.Equal(t, "storage_accounts_public_access", risk.Name)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Contains(t, risk.ImpactedARN, "mystorage")

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Equal(t, "storage_accounts_public_access", ctx["templateId"])
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
