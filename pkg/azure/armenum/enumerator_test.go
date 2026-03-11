package armenum

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// TestARMEnumerator_List_NilCred verifies List returns nil (not panic) when
// the ARM client calls fail with an auth error. handleListError suppresses auth failures.
func TestARMEnumerator_List_NilCred(t *testing.T) {
	e := NewARMEnumerator(nil)
	sub := azuretypes.SubscriptionInfo{ID: "00000000-0000-0000-0000-000000000000"}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := e.List(sub, out)
		// All auth errors are swallowed by handleListError; nil expected.
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	// No real Azure connection: expect empty result, not a panic.
	assert.Empty(t, items)
}

func TestARMEnumerator_ResourceTypesConstant(t *testing.T) {
	// Ensure the documented resource types match what the extractors expect.
	expected := []string{
		"Microsoft.Resources/deployments",
		"Microsoft.Authorization/policyDefinitions",
		"Microsoft.Blueprint/blueprints",
	}
	assert.Equal(t, expected, ARMEnumeratedTypes)
}

func TestHandleListError_Nil(t *testing.T) {
	assert.NoError(t, handleListError(nil, "kind", "sub"))
}

func TestHandleListError_SuppressesAuthErrors(t *testing.T) {
	for _, msg := range []string{
		"AuthorizationFailed: no auth",
		"AuthenticationFailed: bad token",
		"LinkedAuthorizationFailed: scope",
		"RESPONSE 403: Forbidden",
		"RESPONSE 401: Unauthorized",
		"RESPONSE 404: Not Found",
		"RESPONSE 429: Too Many Requests",
	} {
		err := handleListError(errors.New(msg), "kind", "sub")
		assert.NoError(t, err, "expected nil for message: %s", msg)
	}
}

func TestHandleListError_ReturnsRealErrors(t *testing.T) {
	err := handleListError(errors.New("connection timeout"), "kind", "sub-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind")
	assert.Contains(t, err.Error(), "sub-123")
	assert.Contains(t, err.Error(), "connection timeout")
}

func TestIsAuthOrThrottle(t *testing.T) {
	tests := []struct {
		msg      string
		expected bool
	}{
		{"AuthorizationFailed: the caller does not have permission", true},
		{"AuthenticationFailed: invalid token", true},
		{"LinkedAuthorizationFailed: scope", true},
		{"RESPONSE 403: Forbidden", true},
		{"RESPONSE 401: Unauthorized", true},
		{"RESPONSE 404: Not Found", true},
		{"RESPONSE 429: TooManyRequests", true},
		{"connection timeout", false},
		{"internal server error", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAuthOrThrottle(tt.msg))
		})
	}
}

func TestEmitDeployment_NilID(t *testing.T) {
	sub := azuretypes.SubscriptionInfo{ID: "sub-1", DisplayName: "Test", TenantID: "tenant-1"}
	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		emitDeployment(nil, nil, nil, sub, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "nil id should emit nothing")
}

func TestEmitDeployment_AllFields(t *testing.T) {
	id := "/subscriptions/sub-1/providers/Microsoft.Resources/deployments/my-deploy"
	name := "my-deploy"
	loc := "eastus"
	sub := azuretypes.SubscriptionInfo{ID: "sub-1", DisplayName: "Test Sub", TenantID: "tenant-1"}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		emitDeployment(&id, &name, &loc, sub, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	r := items[0]
	assert.Equal(t, id, r.ResourceID)
	assert.Equal(t, "Microsoft.Resources/deployments", r.ResourceType)
	assert.Equal(t, "sub-1", r.SubscriptionID)
	assert.Equal(t, "Test Sub", r.SubscriptionName)
	assert.Equal(t, "tenant-1", r.TenantID)
	assert.Equal(t, "my-deploy", r.DisplayName)
	assert.Equal(t, "eastus", r.Location)
}

func TestEmitDeployment_NilNameAndLocation(t *testing.T) {
	id := "/subscriptions/sub-1/providers/Microsoft.Resources/deployments/deploy"
	sub := azuretypes.SubscriptionInfo{ID: "sub-1"}
	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		emitDeployment(&id, nil, nil, sub, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, id, items[0].ResourceID)
	assert.Empty(t, items[0].DisplayName)
	assert.Empty(t, items[0].Location)
}
