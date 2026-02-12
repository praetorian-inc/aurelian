package plugin_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterEnricher(t *testing.T) {
	// Clear registry for test isolation
	plugin.ResetEnricherRegistry()

	// Register enricher for Lambda functions
	called := false
	enricher := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		called = true
		r.Properties["TestProperty"] = "value"
		return nil
	}

	plugin.RegisterEnricher("AWS::Lambda::Function", enricher)

	// Verify enricher was registered
	enrichers := plugin.GetEnrichers("AWS::Lambda::Function")
	require.Len(t, enrichers, 1, "Should have 1 enricher registered")

	// Execute enricher
	resource := &output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		Properties:   make(map[string]any),
	}
	cfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: aws.Config{},
	}

	err := enrichers[0](cfg, resource)
	assert.NoError(t, err)
	assert.True(t, called, "Enricher should have been called")
	assert.Equal(t, "value", resource.Properties["TestProperty"])
}

func TestMultipleEnrichersPerType(t *testing.T) {
	plugin.ResetEnricherRegistry()

	// Register two enrichers for the same resource type
	enricher1 := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		r.Properties["Enricher1"] = "ran"
		return nil
	}
	enricher2 := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		r.Properties["Enricher2"] = "ran"
		return nil
	}

	plugin.RegisterEnricher("AWS::Lambda::Function", enricher1)
	plugin.RegisterEnricher("AWS::Lambda::Function", enricher2)

	// Verify both enrichers are registered
	enrichers := plugin.GetEnrichers("AWS::Lambda::Function")
	require.Len(t, enrichers, 2, "Should have 2 enrichers registered")

	// Execute both enrichers
	resource := &output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		Properties:   make(map[string]any),
	}
	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}

	for _, enrich := range enrichers {
		err := enrich(cfg, resource)
		assert.NoError(t, err)
	}

	// Verify both ran
	assert.Equal(t, "ran", resource.Properties["Enricher1"])
	assert.Equal(t, "ran", resource.Properties["Enricher2"])
}
