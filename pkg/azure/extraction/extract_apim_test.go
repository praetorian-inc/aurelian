package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAPIM_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.apimanagement/service")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.apimanagement/service")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "apim-policies")
	assert.Contains(t, names, "apim-backends")
	assert.Contains(t, names, "apim-namedvalues")
}
