//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzurePublicResourcesModule(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("azure public-resources module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	p1 := pipeline.From(plugin.Config{
		Args: map[string]any{
			"subscription-id": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "should emit at least one public-azure-resource risk")

	for _, risk := range risks {
		assert.Equal(t, "public-azure-resource", risk.Name)
		assert.NotEmpty(t, risk.ImpactedARN)
		assert.Contains(t, []output.RiskSeverity{
			output.RiskSeverityHigh,
			output.RiskSeverityMedium,
			output.RiskSeverityLow,
		}, risk.Severity)
	}

	t.Run("detects public storage account", func(t *testing.T) {
		resourceID := fixture.Output("storage_account_id")
		assertRiskForResource(t, risks, resourceID, "storage_accounts_public_access")
	})

	t.Run("detects public sql server", func(t *testing.T) {
		resourceID := fixture.Output("sql_server_id")
		assertRiskForResource(t, risks, resourceID, "sql_servers_public_access")
	})

	t.Run("detects public key vault", func(t *testing.T) {
		resourceID := fixture.Output("key_vault_id")
		assertRiskForResource(t, risks, resourceID, "key_vault_public_access")
	})

	t.Run("detects public app service", func(t *testing.T) {
		resourceID := fixture.Output("web_app_id")
		assertRiskForResource(t, risks, resourceID, "app_services_public_access")
	})

	t.Run("detects public container registry", func(t *testing.T) {
		resourceID := fixture.Output("container_registry_id")
		assertRiskForResource(t, risks, resourceID, "container_registries_public_access")
	})

	t.Run("detects public data factory", func(t *testing.T) {
		resourceID := fixture.Output("data_factory_id")
		assertRiskForResource(t, risks, resourceID, "data_factory_public_access")
	})
}

func assertRiskForResource(t *testing.T, risks []output.AurelianRisk, resourceID, templateID string) {
	t.Helper()

	lowerResourceID := strings.ToLower(resourceID)

	for _, risk := range risks {
		lowerImpacted := strings.ToLower(risk.ImpactedARN)
		if lowerImpacted != lowerResourceID {
			continue
		}

		var ctx map[string]any
		if err := json.Unmarshal(risk.Context, &ctx); err != nil {
			continue
		}

		if tid, ok := ctx["templateId"].(string); ok && tid == templateID {
			t.Logf("found risk: template=%s resource=%s severity=%s", templateID, resourceID, risk.Severity)
			return
		}
	}

	t.Errorf("expected risk with templateId=%q for resource %q (checked %d risks)", templateID, resourceID, len(risks))
}
