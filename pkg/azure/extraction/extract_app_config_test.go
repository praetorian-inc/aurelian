package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAppConfig_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.appconfiguration/configurationstores")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.appconfiguration/configurationstores")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "app-config-keyvalues")
}
