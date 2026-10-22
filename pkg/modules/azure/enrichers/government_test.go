package enrichers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestDatabaseFirewallUsesGovernmentSynapseProvider(t *testing.T) {
	for _, tc := range []struct {
		cloud, resourceType, errorText, scope string
	}{
		{"gcc-high", "Microsoft.Synapse/workspaces", "listing Synapse firewall rules", "https://management.core.usgovcloudapi.net//.default"},
		{"gcc-high", "Microsoft.Sql/servers", "listing SQL firewall rules", "https://management.core.usgovcloudapi.net//.default"},
		{"public", "Microsoft.Synapse/workspaces", "listing SQL firewall rules", "https://management.core.windows.net//.default"},
	} {
		t.Run(tc.cloud+"/"+tc.resourceType, func(t *testing.T) {
			cred := &azuretest.Credential{Err: errors.New("offline")}
			cfg := plugin.AzureEnricherConfig{Context: context.Background(), Credential: cred, Env: azurecloud.Resolve(tc.cloud)}
			found, err := checkFirewallRules(cfg, "sub", "rg", "database", tc.resourceType)
			require.ErrorContains(t, err, tc.errorText)
			assert.False(t, found)
			assert.Equal(t, []string{tc.scope}, cred.Scopes)
		})
	}
}
