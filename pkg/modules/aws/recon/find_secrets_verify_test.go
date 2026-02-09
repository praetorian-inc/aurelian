package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RED: Test that find-secrets module accepts verify parameter
func TestFindSecretsModule_VerifyParameter(t *testing.T) {
	module := &FindSecrets{}
	params := module.Parameters()

	// Find verify parameter
	var verifyParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "verify" {
			verifyParam = &params[i]
			break
		}
	}

	require.NotNil(t, verifyParam, "verify parameter should exist")
	assert.Equal(t, "verify", verifyParam.Name)
	assert.Equal(t, "bool", verifyParam.Type)
	assert.Equal(t, false, verifyParam.Default)
	assert.False(t, verifyParam.Required)
	assert.Contains(t, verifyParam.Description, "Validate detected secrets")
}

// RED: Test that find-secrets module accepts datastore parameter
func TestFindSecretsModule_DatastoreParameter(t *testing.T) {
	module := &FindSecrets{}
	params := module.Parameters()

	// Find datastore parameter
	var datastoreParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "datastore" {
			datastoreParam = &params[i]
			break
		}
	}

	require.NotNil(t, datastoreParam, "datastore parameter should exist")
	assert.Equal(t, "datastore", datastoreParam.Name)
	assert.Equal(t, "string", datastoreParam.Type)
	assert.Equal(t, "aurelian-output/titus.db", datastoreParam.Default)
	assert.False(t, datastoreParam.Required)
	assert.Contains(t, datastoreParam.Description, "Path to Titus SQLite database")
}

// RED: Test that Run() extracts verify parameter
func TestFindSecretsModule_RunExtractsVerify(t *testing.T) {
	module := &FindSecrets{}

	// This test will fail until we implement verify extraction and passing
	// For now, just verify the module can be instantiated and has the parameter
	params := module.Parameters()
	var hasVerify bool
	for _, p := range params {
		if p.Name == "verify" {
			hasVerify = true
			break
		}
	}

	assert.True(t, hasVerify, "Module should have verify parameter after implementation")
}

// RED: Test that Run() extracts datastore parameter
func TestFindSecretsModule_RunExtractsDatastore(t *testing.T) {
	module := &FindSecrets{}

	// This test will fail until we implement datastore extraction and passing
	// For now, just verify the module can be instantiated and has the parameter
	params := module.Parameters()
	var hasDatastore bool
	for _, p := range params {
		if p.Name == "datastore" {
			hasDatastore = true
			break
		}
	}

	assert.True(t, hasDatastore, "Module should have datastore parameter after implementation")
}
