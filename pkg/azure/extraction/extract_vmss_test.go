package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVMSSExtractorsRegistered(t *testing.T) {
	extractors := getExtractors("microsoft.compute/virtualmachinescalesets")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.compute/virtualmachinescalesets")

	names := make(map[string]bool)
	for _, e := range extractors {
		names[e.Name] = true
	}
	for _, want := range []string{"vmss-userdata", "vmss-extensions"} {
		if !names[want] {
			t.Errorf("extractor %q not registered", want)
		}
	}
}
