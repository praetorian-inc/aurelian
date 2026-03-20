package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractVM_RegisteredTypes(t *testing.T) {
	// Verify VM extractors are registered for the correct resource type
	extractors := getExtractors("microsoft.compute/virtualmachines")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.compute/virtualmachines")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "vm-userdata")
	assert.Contains(t, names, "vm-extensions")
}
