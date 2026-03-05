package resourcegraph

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseARGTemplateRow_StandardFields(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{
		ID:       "test_template",
		Name:     "Test Template",
		Severity: "high",
		Query:    "resources | where true",
	}

	row := map[string]any{
		"id":             "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
		"name":           "sa1",
		"type":           "Microsoft.Storage/storageAccounts",
		"location":       "eastus",
		"subscriptionId": "sub1",
		"customField":    "customValue",
	}

	result, err := parseARGTemplateRow(row, tmpl)
	require.NoError(t, err)

	assert.Equal(t, "test_template", result.TemplateID)
	assert.Equal(t, tmpl, result.TemplateDetails)
	assert.Equal(t, "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1", result.ResourceID)
	assert.Equal(t, "sa1", result.ResourceName)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", result.ResourceType)
	assert.Equal(t, "eastus", result.Location)
	assert.Equal(t, "sub1", result.SubscriptionID)
	assert.Equal(t, "customValue", result.Properties["customField"])
}

func TestParseARGTemplateRow_NoExtraProperties(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{
		ID:       "minimal",
		Name:     "Minimal",
		Severity: "low",
		Query:    "resources",
	}

	row := map[string]any{
		"id":   "/subscriptions/sub1/providers/test",
		"name": "test",
		"type": "Microsoft.Test/resource",
	}

	result, err := parseARGTemplateRow(row, tmpl)
	require.NoError(t, err)
	assert.Nil(t, result.Properties)
}

func TestParseARGTemplateRow_InvalidRowType(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{ID: "test"}
	_, err := parseARGTemplateRow("not-a-map", tmpl)
	assert.Error(t, err)
}
