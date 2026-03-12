package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerAppExtractorsRegistered(t *testing.T) {
	extractors := getExtractors("microsoft.app/containerapps")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.app/containerapps")

	names := make(map[string]bool)
	for _, e := range extractors {
		names[e.Name] = true
	}
	for _, want := range []string{"container-app-envvars"} {
		if !names[want] {
			t.Errorf("extractor %q not registered", want)
		}
	}
}
