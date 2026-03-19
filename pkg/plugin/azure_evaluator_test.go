package plugin

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestRegisterAndGetAzureEvaluator(t *testing.T) {
	defer ResetAzureEvaluatorRegistry()

	RegisterAzureEvaluator("test_tmpl", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["flag"].(bool)
		return ok && v
	})

	fn, ok := GetAzureEvaluator("test_tmpl")
	assert.True(t, ok)
	assert.True(t, fn(templates.ARGQueryResult{Properties: map[string]any{"flag": true}}))
	assert.False(t, fn(templates.ARGQueryResult{Properties: map[string]any{"flag": false}}))
}

func TestGetAzureEvaluator_Unregistered(t *testing.T) {
	defer ResetAzureEvaluatorRegistry()
	_, ok := GetAzureEvaluator("nonexistent")
	assert.False(t, ok)
}

func TestResetAzureEvaluatorRegistry(t *testing.T) {
	RegisterAzureEvaluator("tmpl", func(_ templates.ARGQueryResult) bool { return true })
	ResetAzureEvaluatorRegistry()
	_, ok := GetAzureEvaluator("tmpl")
	assert.False(t, ok)
}
