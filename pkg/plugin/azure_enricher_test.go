package plugin

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestRegisterAndGetAzureEnricher(t *testing.T) {
	defer ResetAzureEnricherRegistry()

	called := false
	fn := func(_ AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		called = true
		return true, nil
	}

	RegisterAzureEnricher("test_template", fn)
	enrichers := GetAzureEnrichers("test_template")

	assert.Len(t, enrichers, 1)
	ok, err := enrichers[0](AzureEnricherConfig{Context: context.Background()}, templates.ARGQueryResult{})
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, called)
}

func TestGetAzureEnrichers_Unregistered(t *testing.T) {
	defer ResetAzureEnricherRegistry()

	enrichers := GetAzureEnrichers("nonexistent")
	assert.Empty(t, enrichers)
}

func TestRegisterAzureEnricher_MultiplePerTemplate(t *testing.T) {
	defer ResetAzureEnricherRegistry()

	RegisterAzureEnricher("tmpl", func(_ AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) { return true, nil })
	RegisterAzureEnricher("tmpl", func(_ AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) { return false, nil })

	assert.Len(t, GetAzureEnrichers("tmpl"), 2)
}

func TestResetAzureEnricherRegistry(t *testing.T) {
	RegisterAzureEnricher("tmpl", func(_ AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) { return true, nil })
	ResetAzureEnricherRegistry()
	assert.Empty(t, GetAzureEnrichers("tmpl"))
}
