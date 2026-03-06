package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDataFactory_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.datafactory/factories")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.datafactory/factories")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "adf-pipelines")
	assert.Contains(t, names, "adf-linkedservices")
}
