package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDeployments_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.resources/deployments")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.resources/deployments")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "deployment-params")
}
