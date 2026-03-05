package resourcegraph

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplateRow(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{
		ID:       "test-template",
		Name:     "Test Template",
		Severity: "high",
	}

	row := map[string]any{
		"id":             "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/myapp",
		"name":           "myapp",
		"type":           "Microsoft.Web/sites",
		"location":       "eastus",
		"subscriptionId": "sub-1",
		"customField":    "customValue",
	}

	result := parseTemplateRow(row, tmpl)

	assert.Equal(t, "test-template", result.TemplateID)
	assert.Equal(t, tmpl, result.TemplateDetails)
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/myapp", result.ResourceID)
	assert.Equal(t, "myapp", result.ResourceName)
	assert.Equal(t, "Microsoft.Web/sites", result.ResourceType)
	assert.Equal(t, "eastus", result.Location)
	assert.Equal(t, "sub-1", result.SubscriptionID)
	assert.Equal(t, "customValue", result.Properties["customField"])
}

func TestParseTemplateRow_MinimalFields(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{ID: "minimal"}

	row := map[string]any{
		"id": "/subscriptions/sub-1/providers/something",
	}

	result := parseTemplateRow(row, tmpl)
	assert.Equal(t, "minimal", result.TemplateID)
	assert.Equal(t, "/subscriptions/sub-1/providers/something", result.ResourceID)
	assert.Empty(t, result.ResourceName)
}
