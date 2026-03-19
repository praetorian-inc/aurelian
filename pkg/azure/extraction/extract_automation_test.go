package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAutomation_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.automation/automationaccounts")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.automation/automationaccounts")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "automation-variables")
	assert.Contains(t, names, "automation-runbooks")
}
