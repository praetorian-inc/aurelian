package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskFromQueryResult_ValidResult(t *testing.T) {
	out := pipeline.New[model.AurelianModel]()

	r := templates.ARGQueryResult{
		TemplateID: "test-template",
		TemplateDetails: &templates.ARGQueryTemplate{
			ID:       "test-template",
			Name:     "Test",
			Severity: "high",
		},
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/myapp",
		ResourceName:   "myapp",
		ResourceType:   "Microsoft.Web/sites",
		Location:       "eastus",
		SubscriptionID: "sub-1",
	}

	go func() {
		defer out.Close()
		err := riskFromQueryResult(r, out)
		require.NoError(t, err)
	}()

	results, _ := out.Collect()
	require.Len(t, results, 1)

	risk, ok := results[0].(output.AurelianRisk)
	require.True(t, ok)
	assert.Equal(t, "public-azure-resource", risk.Name)
	assert.Equal(t, output.RiskSeverity("high"), risk.Severity)
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/myapp", risk.ImpactedARN)
	assert.NotEmpty(t, risk.Context)

	var ctx map[string]any
	err := json.Unmarshal(risk.Context, &ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-template", ctx["templateId"])
}

func TestRiskFromQueryResult_EmptyResourceID(t *testing.T) {
	out := pipeline.New[model.AurelianModel]()

	r := templates.ARGQueryResult{
		TemplateID: "test-template",
		TemplateDetails: &templates.ARGQueryTemplate{
			Severity: "medium",
		},
		ResourceID: "",
	}

	go func() {
		defer out.Close()
		err := riskFromQueryResult(r, out)
		require.NoError(t, err)
	}()

	results, _ := out.Collect()
	assert.Empty(t, results, "should skip results with empty ResourceID")
}
