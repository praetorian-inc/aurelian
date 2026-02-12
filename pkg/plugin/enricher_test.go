package plugin_test

import (
	"context"
	"fmt"
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

func TestEnricherErrorHandling(t *testing.T) {
	plugin.ResetEnricherRegistry()

	// Enricher that returns an error
	enricher := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		return fmt.Errorf("enrichment failed")
	}

	plugin.RegisterEnricher("AWS::S3::Bucket", enricher)

	// Execute enricher
	resource := &output.CloudResource{
		ResourceType: "AWS::S3::Bucket",
		Properties:   make(map[string]any),
	}
	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}

	enrichers := plugin.GetEnrichers("AWS::S3::Bucket")
	err := enrichers[0](cfg, resource)

	// Verify error is returned (caller decides whether to log or fail)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "enrichment failed")
}

func TestEnricherPropertiesMutation(t *testing.T) {
	plugin.ResetEnricherRegistry()

	// Enricher that adds multiple properties
	enricher := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		r.Properties["FunctionUrl"] = "https://abc123.lambda-url.us-east-1.on.aws/"
		r.Properties["FunctionUrlAuthType"] = "AWS_IAM"
		r.Properties["EnrichedAt"] = "2026-02-11T23:23:08Z"
		return nil
	}

	plugin.RegisterEnricher("AWS::Lambda::Function", enricher)

	// Execute enricher
	resource := &output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		Properties:   map[string]any{"ExistingProp": "value"},
	}
	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}

	enrichers := plugin.GetEnrichers("AWS::Lambda::Function")
	err := enrichers[0](cfg, resource)

	assert.NoError(t, err)
	// Verify all properties added
	assert.Equal(t, "https://abc123.lambda-url.us-east-1.on.aws/", resource.Properties["FunctionUrl"])
	assert.Equal(t, "AWS_IAM", resource.Properties["FunctionUrlAuthType"])
	assert.Equal(t, "2026-02-11T23:23:08Z", resource.Properties["EnrichedAt"])
	// Verify existing properties preserved
	assert.Equal(t, "value", resource.Properties["ExistingProp"])
}

func TestGetEnrichersUnknownType(t *testing.T) {
	plugin.ResetEnricherRegistry()

	// Register enricher for Lambda
	enricher := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		return nil
	}
	plugin.RegisterEnricher("AWS::Lambda::Function", enricher)

	// Request enrichers for different type
	enrichers := plugin.GetEnrichers("AWS::S3::Bucket")

	// Verify empty slice returned (not nil, not error)
	assert.NotNil(t, enrichers)
	assert.Len(t, enrichers, 0)
}
