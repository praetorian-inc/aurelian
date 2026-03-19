package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerInstanceExtractorsRegistered(t *testing.T) {
	extractors := getExtractors("microsoft.containerinstance/containergroups")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.containerinstance/containergroups")

	names := make(map[string]bool)
	for _, e := range extractors {
		names[e.Name] = true
	}
	for _, want := range []string{"container-instance-envvars"} {
		if !names[want] {
			t.Errorf("extractor %q not registered", want)
		}
	}
}
