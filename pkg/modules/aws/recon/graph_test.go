package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSGraphModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryAnalyze, "graph")
	require.True(t, ok, "graph module should be registered")
	require.NotNil(t, mod)
}

func TestAWSGraphModuleMetadata(t *testing.T) {
	m := &AWSGraphModule{}
	assert.Equal(t, "graph", m.ID())
	assert.Equal(t, "AWS Graph Analysis", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryAnalyze, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])
}

func TestAWSGraphModuleParameters(t *testing.T) {
	m := &AWSGraphModule{}
	params := plugin.ParametersFrom(m.Parameters())

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	// Must include Neo4j params from GraphOutputBase
	assert.True(t, paramNames["neo4j-uri"], "should have neo4j-uri param")
	assert.True(t, paramNames["neo4j-username"], "should have neo4j-username param")
	assert.True(t, paramNames["neo4j-password"], "should have neo4j-password param")

	// Must include AWS params from AWSCommonRecon
	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")

	// Must include org-policies-file
	assert.True(t, paramNames["org-policies-file"], "should have org-policies-file param")
}

func TestGraphResolveRegions(t *testing.T) {
	// Non-"all" should pass through unchanged
	regions, err := graphResolveRegions([]string{"us-east-1", "us-west-2"}, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, regions)

	// Single non-all region
	regions, err = graphResolveRegions([]string{"eu-west-1"}, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu-west-1"}, regions)
}
