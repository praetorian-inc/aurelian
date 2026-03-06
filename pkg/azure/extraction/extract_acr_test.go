package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractACR_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.containerregistry/registries")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.containerregistry/registries")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "acr-tasks")
}
