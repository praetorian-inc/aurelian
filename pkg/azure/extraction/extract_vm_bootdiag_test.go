package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVMBootDiagExtractorRegistered(t *testing.T) {
	extractors := getExtractors("microsoft.compute/virtualmachines")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.compute/virtualmachines")

	names := make(map[string]bool)
	for _, e := range extractors {
		names[e.Name] = true
	}
	for _, want := range []string{"vm-bootdiag"} {
		if !names[want] {
			t.Errorf("extractor %q not registered", want)
		}
	}
}
