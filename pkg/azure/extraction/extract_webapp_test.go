package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWebApp_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.web/sites")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.web/sites")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "webapp-settings")
	assert.Contains(t, names, "webapp-connections")
	assert.Contains(t, names, "webapp-hostkeys")
	assert.Contains(t, names, "webapp-slots")
	assert.Contains(t, names, "webapp-siteconfig")
}
