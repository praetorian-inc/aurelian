package enumeration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildIdentityPoolResourceUnauthEnabled(t *testing.T) {
	// GetIdentityPoolRoles keys roles by "authenticated"/"unauthenticated"; the builder
	// suffixes "Role" so the bound ARNs land as quoted values resource_service_role.yaml
	// substring-matches to create the (IdentityPool)-[:HAS_ROLE]->(Role) edges.
	boundRoles := map[string]string{
		"authenticated":   "arn:aws:iam::123456789012:role/pl-prod-idp-007-auth-role",
		"unauthenticated": "arn:aws:iam::123456789012:role/pl-prod-idp-007-unauth-role",
	}

	r := buildIdentityPoolResource("us-east-1:pool-007", "pl-prod-idp-007", true, boundRoles, "123456789012", "us-east-1")

	assert.Equal(t, "AWS::Cognito::IdentityPool", r.ResourceType)
	assert.Equal(t, "us-east-1:pool-007", r.ResourceID)
	assert.Equal(t, "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/us-east-1:pool-007", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "pl-prod-idp-007", r.DisplayName)
	// AllowUnauthenticatedIdentities relaxes cognito_set_identity_pool_roles' GetId/GetCredentials guard.
	assert.Equal(t, true, r.Properties["AllowUnauthenticatedIdentities"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/pl-prod-idp-007-auth-role", r.Properties["authenticatedRole"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/pl-prod-idp-007-unauth-role", r.Properties["unauthenticatedRole"])
}

func TestBuildIdentityPoolResourceUnauthDisabled(t *testing.T) {
	// Auth-only pool: AllowUnauthenticatedIdentities false; only the authenticated role is bound.
	boundRoles := map[string]string{
		"authenticated": "arn:aws:iam::123456789012:role/pl-prod-idp-008-auth-role",
	}

	r := buildIdentityPoolResource("us-west-2:pool-008", "pl-prod-idp-008", false, boundRoles, "123456789012", "us-west-2")

	assert.Equal(t, "us-west-2:pool-008", r.ResourceID)
	assert.Equal(t, false, r.Properties["AllowUnauthenticatedIdentities"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/pl-prod-idp-008-auth-role", r.Properties["authenticatedRole"])
	// No unauthenticated role bound, so the property is absent (empty ARNs are skipped).
	_, hasUnauth := r.Properties["unauthenticatedRole"]
	assert.False(t, hasUnauth)
}

func TestBuildIdentityPoolResourceSkipsEmptyRoleARN(t *testing.T) {
	// An empty role ARN is fail-closed: no property is emitted, so resource_service_role.yaml
	// cannot match it to any role.
	boundRoles := map[string]string{
		"authenticated":   "arn:aws:iam::123456789012:role/pl-prod-idp-009-auth-role",
		"unauthenticated": "",
	}

	r := buildIdentityPoolResource("us-east-1:pool-009", "pl-prod-idp-009", true, boundRoles, "123456789012", "us-east-1")

	assert.Equal(t, "arn:aws:iam::123456789012:role/pl-prod-idp-009-auth-role", r.Properties["authenticatedRole"])
	_, hasUnauth := r.Properties["unauthenticatedRole"]
	assert.False(t, hasUnauth)
}
