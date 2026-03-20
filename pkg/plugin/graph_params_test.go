package plugin_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGraphOutputBase_StructTags(t *testing.T) {
	// Test that GraphOutputBase has correct struct tags for parameter binding
	var base plugin.GraphOutputBase

	params, err := plugin.ParametersFrom(base)
	require.NoError(t, err)

	// Verify we have exactly 3 parameters
	assert.Len(t, params, 3, "GraphOutputBase should define 3 parameters")

	// Find each parameter by name
	var neo4jURI, neo4jUsername, neo4jPassword *plugin.Parameter
	for i := range params {
		switch params[i].Name {
		case "neo4j-uri":
			neo4jURI = &params[i]
		case "neo4j-username":
			neo4jUsername = &params[i]
		case "neo4j-password":
			neo4jPassword = &params[i]
		}
	}

	// Verify neo4j-uri parameter
	assert.NotNil(t, neo4jURI, "neo4j-uri parameter should exist")
	if neo4jURI != nil {
		assert.Equal(t, "neo4j-uri", neo4jURI.Name)
		assert.Equal(t, "Neo4j connection URI (e.g., bolt://localhost:7687)", neo4jURI.Description)
		// When default:"" is specified, ParametersFrom returns nil (not empty string)
		assert.Nil(t, neo4jURI.Default, "neo4j-uri with default:\"\" should have nil Default")
	}

	// Verify neo4j-username parameter
	assert.NotNil(t, neo4jUsername, "neo4j-username parameter should exist")
	if neo4jUsername != nil {
		assert.Equal(t, "neo4j-username", neo4jUsername.Name)
		assert.Equal(t, "Neo4j username", neo4jUsername.Description)
		assert.Equal(t, "neo4j", neo4jUsername.Default)
	}

	// Verify neo4j-password parameter (sensitive)
	assert.NotNil(t, neo4jPassword, "neo4j-password parameter should exist")
	if neo4jPassword != nil {
		assert.Equal(t, "neo4j-password", neo4jPassword.Name)
		assert.Equal(t, "Neo4j password", neo4jPassword.Description)
		assert.Equal(t, "neo4j", neo4jPassword.Default)
		assert.True(t, neo4jPassword.Sensitive, "neo4j-password should be marked as sensitive")
	}
}

func TestGraphOutputBase_Embedding(t *testing.T) {
	// Test that GraphOutputBase can be embedded in a module config
	type TestModuleConfig struct {
		plugin.GraphOutputBase
		SomeOtherParam string `param:"other" desc:"Another parameter"`
	}

	var cfg TestModuleConfig
	params, err := plugin.ParametersFrom(cfg)
	require.NoError(t, err)

	// Should have 4 parameters total (3 from GraphOutputBase + 1 from TestModuleConfig)
	assert.Len(t, params, 4, "Embedded GraphOutputBase parameters should be extracted")

	// Verify at least one GraphOutputBase parameter exists
	found := false
	for _, p := range params {
		if p.Name == "neo4j-uri" {
			found = true
			break
		}
	}
	assert.True(t, found, "neo4j-uri from embedded GraphOutputBase should be present")
}

func TestGraphOutputBase_FieldAccess(t *testing.T) {
	// Test that struct fields are accessible and have correct Go types
	base := plugin.GraphOutputBase{
		Neo4jURI:      "bolt://localhost:7687",
		Neo4jUsername: "testuser",
		Neo4jPassword: "testpass",
	}

	assert.Equal(t, "bolt://localhost:7687", base.Neo4jURI)
	assert.Equal(t, "testuser", base.Neo4jUsername)
	assert.Equal(t, "testpass", base.Neo4jPassword)
}

func TestGraphOutputBase_UsageExample(t *testing.T) {
	// Demonstrate typical usage pattern matching AWSCommonRecon
	type GraphExportConfig struct {
		plugin.GraphOutputBase
		ExportFormat string `param:"format" desc:"Export format" default:"cypher"`
		BatchSize    int    `param:"batch-size" desc:"Batch size for graph writes" default:"100"`
	}

	var cfg GraphExportConfig
	params, err := plugin.ParametersFrom(cfg)
	require.NoError(t, err)

	// Should have 5 parameters (3 from GraphOutputBase + 2 from GraphExportConfig)
	assert.Len(t, params, 5)

	// Verify all Neo4j parameters are present
	paramNames := make([]string, len(params))
	for i, p := range params {
		paramNames[i] = p.Name
	}
	assert.Contains(t, paramNames, "neo4j-uri")
	assert.Contains(t, paramNames, "neo4j-username")
	assert.Contains(t, paramNames, "neo4j-password")
	assert.Contains(t, paramNames, "format")
	assert.Contains(t, paramNames, "batch-size")
}

func TestParametersFrom_RejectsUntaggedExportedField(t *testing.T) {
	type BadConfig struct {
		Tagged   string `param:"tagged" desc:"This is fine"`
		Untagged string // exported, no param tag — should error
	}

	_, err := plugin.ParametersFrom(BadConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Untagged")
	assert.Contains(t, err.Error(), "no `param` tag")
}

func TestParametersFrom_AllowsExplicitSkip(t *testing.T) {
	type SkipConfig struct {
		Tagged  string `param:"tagged" desc:"This is fine"`
		Skipped string `param:"-"`
	}

	params, err := plugin.ParametersFrom(SkipConfig{})
	require.NoError(t, err)
	assert.Len(t, params, 1)
	assert.Equal(t, "tagged", params[0].Name)
}

func TestParametersFrom_AllowsUnexportedFields(t *testing.T) {
	type InternalConfig struct {
		Tagged   string `param:"tagged" desc:"This is fine"`
		internal string //nolint:unused // unexported, no tag — should be fine
	}

	params, err := plugin.ParametersFrom(InternalConfig{})
	require.NoError(t, err)
	assert.Len(t, params, 1)
}

func TestParametersFrom_RejectsUntaggedInEmbeddedStruct(t *testing.T) {
	type EmbeddedBase struct {
		Good    string `param:"good" desc:"tagged"`
		BadField string // exported, no param tag
	}
	type Config struct {
		EmbeddedBase
	}

	_, err := plugin.ParametersFrom(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BadField")
}

func TestParametersFrom_NilReturnsNil(t *testing.T) {
	params, err := plugin.ParametersFrom(nil)
	require.NoError(t, err)
	assert.Nil(t, params)
}
