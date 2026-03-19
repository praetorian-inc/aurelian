package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDigitalTwins_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.digitaltwins/digitaltwinsinstances")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.digitaltwins/digitaltwinsinstances")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "digitaltwins-properties")
}
