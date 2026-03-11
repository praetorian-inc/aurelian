package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArcExtractorsRegistered(t *testing.T) {
	extractors := getExtractors("microsoft.hybridcompute/machines")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.hybridcompute/machines")

	names := make(map[string]bool)
	for _, e := range extractors {
		names[e.Name] = true
	}
	for _, want := range []string{"arc-extensions"} {
		if !names[want] {
			t.Errorf("extractor %q not registered", want)
		}
	}
}
