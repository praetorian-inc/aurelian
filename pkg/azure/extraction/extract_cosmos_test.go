package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCosmos_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.documentdb/databaseaccounts")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.documentdb/databaseaccounts")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "cosmos-storedprocs")
	assert.Contains(t, names, "cosmos-triggers")
	assert.Contains(t, names, "cosmos-udfs")
	assert.Contains(t, names, "cosmos-config-docs")
}
