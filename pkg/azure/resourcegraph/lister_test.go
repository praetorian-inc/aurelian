package resourcegraph

import (
	"testing"
)

func TestBuildListByTypesQuery(t *testing.T) {
	types := []string{"Microsoft.Compute/virtualMachines", "Microsoft.Web/sites"}
	query := buildListByTypesQuery(types)

	expected := "Resources | where type in~ ('microsoft.compute/virtualmachines','microsoft.web/sites') | project id, name, type, location, resourceGroup, tags, properties"
	if query != expected {
		t.Errorf("unexpected query:\ngot:  %s\nwant: %s", query, expected)
	}
}

func TestBuildListByTypesQuery_SingleType(t *testing.T) {
	types := []string{"Microsoft.Storage/storageAccounts"}
	query := buildListByTypesQuery(types)

	expected := "Resources | where type in~ ('microsoft.storage/storageaccounts') | project id, name, type, location, resourceGroup, tags, properties"
	if query != expected {
		t.Errorf("unexpected query:\ngot:  %s\nwant: %s", query, expected)
	}
}
