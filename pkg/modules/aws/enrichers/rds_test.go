package enrichers_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrichRDSInstance_PubliclyAccessible(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "my-db",
		Properties:   map[string]any{"PubliclyAccessible": true},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichRDSInstance(cfg, resource)
	require.NoError(t, err)
	assert.True(t, resource.Properties["IsPubliclyAccessible"].(bool))
}

func TestEnrichRDSInstance_NotPubliclyAccessible(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "my-db",
		Properties:   map[string]any{"PubliclyAccessible": false},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichRDSInstance(cfg, resource)
	require.NoError(t, err)
	assert.False(t, resource.Properties["IsPubliclyAccessible"].(bool))
}

func TestEnrichRDSInstance_MissingProperty(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "my-db",
		Properties:   map[string]any{},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichRDSInstance(cfg, resource)
	require.NoError(t, err)
	assert.False(t, resource.Properties["IsPubliclyAccessible"].(bool))
}
