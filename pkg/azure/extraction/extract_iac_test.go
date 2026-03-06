package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractIaC_TemplateSpec_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.resources/templatespecs")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.resources/templatespecs")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "template-spec-versions")
}

func TestExtractIaC_Blueprint_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.blueprint/blueprints")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.blueprint/blueprints")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "blueprint-artifacts")
}

func TestExtractIaC_Policy_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.authorization/policydefinitions")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.authorization/policydefinitions")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "policy-definitions")
}
