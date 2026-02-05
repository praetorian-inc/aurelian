package compute

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestInstanceListModuleInterface(t *testing.T) {
	m := &InstanceList{}

	// Test module metadata
	assert.Equal(t, "gcp-instance-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.Description())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.NotEmpty(t, m.OpsecLevel())
	assert.NotEmpty(t, m.Authors())

	// Test parameters
	params := m.Parameters()
	assert.NotEmpty(t, params)
}

func TestInstanceListModuleRun(t *testing.T) {
	m := &InstanceList{}

	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"project":     "test-project",
			"credentials": "",
		},
		Verbose: true,
	}

	// Without valid credentials, this will return an error
	// but should not panic
	results, err := m.Run(cfg)

	// Either results is not nil OR err is not nil (but not both nil)
	assert.True(t, results != nil || err != nil, "Run should return either results or error")
}

func TestInstanceSecretsModuleInterface(t *testing.T) {
	m := &InstanceSecrets{}

	assert.Equal(t, "gcp-instance-secrets", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
}

func TestInstanceInfoModuleInterface(t *testing.T) {
	m := &InstanceInfo{}

	assert.Equal(t, "gcp-instance-info", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
}

func TestGlobalForwardingRuleListModuleInterface(t *testing.T) {
	m := &GlobalForwardingRuleList{}

	assert.Equal(t, "gcp-global-forwarding-rule-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
}

func TestRegionalForwardingRuleListModuleInterface(t *testing.T) {
	m := &RegionalForwardingRuleList{}

	assert.Equal(t, "gcp-regional-forwarding-rule-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
}

func TestGlobalAddressListModuleInterface(t *testing.T) {
	m := &GlobalAddressList{}

	assert.Equal(t, "gcp-global-address-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
}

func TestRegionalAddressListModuleInterface(t *testing.T) {
	m := &RegionalAddressList{}

	assert.Equal(t, "gcp-regional-address-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
}

func TestDnsManagedZoneListModuleInterface(t *testing.T) {
	m := &DnsManagedZoneList{}

	assert.Equal(t, "gcp-dns-managed-zone-list", m.ID())
	assert.NotEmpty(t, m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
}
