package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractStaticWebApp_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.web/staticsites")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.web/staticsites")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "static-webapp-settings")
}
