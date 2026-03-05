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

func TestRiskFromARGResult_EmitsRisk(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{
		ID:          "storage_public",
		Name:        "Public Storage",
		Description: "Detects public storage accounts",
		Severity:    "high",
		TriageNotes: "Check network rules",
	}

	result := templates.ARGQueryResult{
		TemplateID:      tmpl.ID,
		TemplateDetails: tmpl,
		ResourceID:      "/subscriptions/sub1/providers/Microsoft.Storage/storageAccounts/sa1",
		ResourceName:    "sa1",
		ResourceType:    "Microsoft.Storage/storageAccounts",
		Location:        "eastus",
		SubscriptionID:  "sub1",
		Properties:      map[string]any{"publicAccess": true},
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := riskFromARGResult(result, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)

	risk, ok := results[0].(output.AurelianRisk)
	require.True(t, ok)

	assert.Equal(t, "storage_public", risk.Name)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Equal(t, "/subscriptions/sub1/providers/Microsoft.Storage/storageAccounts/sa1", risk.ImpactedARN)

	var ctx map[string]any
	err = json.Unmarshal(risk.Context, &ctx)
	require.NoError(t, err)
	assert.Equal(t, "sa1", ctx["resourceName"])
	assert.Equal(t, "Check network rules", ctx["triageNotes"])
	assert.NotNil(t, ctx["properties"])
}

func TestRiskFromARGResult_NilTemplate(t *testing.T) {
	result := templates.ARGQueryResult{TemplateDetails: nil}
	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		_ = riskFromARGResult(result, out)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected output.RiskSeverity
	}{
		{"critical", output.RiskSeverityCritical},
		{"Critical", output.RiskSeverityCritical},
		{"high", output.RiskSeverityHigh},
		{"High", output.RiskSeverityHigh},
		{"medium", output.RiskSeverityMedium},
		{"low", output.RiskSeverityLow},
		{"info", output.RiskSeverityInfo},
		{"unknown", output.RiskSeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapSeverity(tt.input))
		})
	}
}
