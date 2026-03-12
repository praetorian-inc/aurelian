package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractLogicApp_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.logic/workflows")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.logic/workflows")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "logic-app-definition")
}
