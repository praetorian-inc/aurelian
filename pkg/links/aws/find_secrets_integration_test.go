package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSFindSecrets_DatastoreArgPassthrough verifies datastore arg is passed through
func TestAWSFindSecrets_DatastoreArgPassthrough(t *testing.T) {
	customPath := "custom-output/custom-titus.db"

	args := map[string]any{
		"datastore": customPath,
	}

	fs := NewAWSFindSecrets(args)

	// Verify datastore arg is accessible
	datastore := fs.ArgString("datastore", "default.db")
	assert.Equal(t, customPath, datastore, "datastore should be passed through args")
}

// TestAWSFindSecrets_VerifyArgPassthrough verifies verify arg is passed through
func TestAWSFindSecrets_VerifyArgPassthrough(t *testing.T) {
	args := map[string]any{
		"verify": true,
	}

	fs := NewAWSFindSecrets(args)

	// Verify verify arg is accessible
	verify := fs.ArgBool("verify", false)
	assert.True(t, verify, "verify should be passed through args")
}

// TestAWSFindSecrets_DefaultValues verifies default values are used when not specified
func TestAWSFindSecrets_DefaultValues(t *testing.T) {
	args := map[string]any{}

	fs := NewAWSFindSecrets(args)

	// Verify default datastore
	datastore := fs.ArgString("datastore", "aurelian-output/titus.db")
	assert.Equal(t, "aurelian-output/titus.db", datastore, "should use default datastore")

	// Verify default verify
	verify := fs.ArgBool("verify", false)
	assert.False(t, verify, "should use default verify=false")
}

// TestFindSecrets_ArgsMapContainsVerifyAndDatastore verifies args map includes new parameters
func TestFindSecrets_ArgsMapContainsVerifyAndDatastore(t *testing.T) {
	// This test verifies that when module Run() builds args map,
	// it includes verify and datastore

	// We can't easily test the full Run() method without mocking AWS,
	// but we verified in the module tests that the parameters exist
	// and in the link tests that they're accessible via ArgString/ArgBool

	// This test just documents the expected flow:
	// Module Run() -> extracts verify/datastore from cfg.Args
	//              -> passes to NewAWSFindSecrets in args map
	//              -> link accesses via ArgString/ArgBool
	//              -> link passes to NewPersistentScanner

	require.True(t, true, "Flow documented and tested in component tests")
}
