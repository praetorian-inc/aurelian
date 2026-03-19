package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAppInsights_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.insights/components")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.insights/components")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "app-insights-keys")
}
