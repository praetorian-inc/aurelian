package resourcegraph

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestBuildFilteredQuery(t *testing.T) {
	types := []string{
		"Microsoft.Compute/virtualMachines",
		"Microsoft.Web/sites",
	}
	query := buildFilteredQuery(types)
	expected := "Resources | where type in~ ('microsoft.compute/virtualmachines','microsoft.web/sites') | project id, name, type, kind, location, resourceGroup, tags, properties"
	assert.Equal(t, expected, query)
}

func TestBuildFilteredQuery_Single(t *testing.T) {
	query := buildFilteredQuery([]string{"Microsoft.Storage/storageAccounts"})
	expected := "Resources | where type in~ ('microsoft.storage/storageaccounts') | project id, name, type, kind, location, resourceGroup, tags, properties"
	assert.Equal(t, expected, query)
}

func TestQueryInput_HasRequiredFields(t *testing.T) {
	input := QueryInput{
		Template: &templates.ARGQueryTemplate{
			ID:       "test",
			Name:     "Test",
			Query:    "resources | limit 1",
			Severity: "Low",
		},
	}
	assert.Equal(t, "test", input.Template.ID)
}
