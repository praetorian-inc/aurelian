package enrichers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestGovernmentEnricherSDKPaths(t *testing.T) {
	for _, resourceType := range []string{"Microsoft.Web/sites", "Microsoft.Compute/virtualMachines", "Microsoft.Sql/servers", "Microsoft.DBforPostgreSQL/flexibleServers", "Microsoft.DBforMySQL/flexibleServers", "Microsoft.Synapse/workspaces"} {
		t.Run(resourceType, func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, "gcc-high")
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, "management.usgovcloudapi.net", r.URL.Host)
				assert.Equal(t, "Bearer offline-gcc-high", r.Header.Get("Authorization"))
				return azuretest.JSON(r, `{"value":[],"properties":{"platform":{"enabled":false}}}`), nil
			})
			result := templates.ARGQueryResult{SubscriptionID: "00000000-0000-0000-0000-000000000001", ResourceName: "resource", ResourceType: resourceType, ResourceID: "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/" + resourceType + "/resource", Properties: map[string]any{"kind": "functionapp", "principalId": "11111111-1111-1111-1111-111111111111"}}
			cfg := plugin.AzureEnricherConfig{Context: context.Background(), Credential: cred, Env: env}
			switch {
			case strings.Contains(resourceType, "Microsoft.Web"):
				require.NoError(t, enrichAppServiceAuth(cfg, &result))
				require.NoError(t, enrichRemoteDebugging(cfg, &result))
				require.NoError(t, enrichFunctionAnonymousAccess(cfg, &result))
			case strings.Contains(resourceType, "Microsoft.Compute"):
				require.NoError(t, enrichVMIdentity(cfg, &result))
			default:
				require.NoError(t, enrichDatabaseFirewall(cfg, &result))
			}
			assert.Greater(t, calls, 0)
			for _, scope := range cred.Scopes() {
				assert.Equal(t, env.ARMScope(), scope)
			}
		})
	}
}

func TestEnricherFailuresRemainBestEffortAcrossClouds(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		t.Run(typ, func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, typ)
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				resp := azuretest.JSON(r, `{"error":{"code":"ResourceNotFound","message":"offline unavailable API"}}`)
				resp.StatusCode = 404
				return resp, nil
			})
			cfg := plugin.AzureEnricherConfig{Context: context.Background(), Credential: cred, Env: env}
			for _, fn := range []plugin.AzureEnricherFunc{enrichAppServiceAuth, enrichRemoteDebugging, enrichFunctionAnonymousAccess} {
				result := templates.ARGQueryResult{SubscriptionID: "00000000-0000-0000-0000-000000000001", ResourceName: "site", ResourceID: "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Web/sites/site", Properties: map[string]any{"kind": "functionapp"}}
				err := fn(cfg, &result)
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"kind": "functionapp"}, result.Properties)
			}
		})
	}
}

func TestGovernmentSynapseFirewallUsesWorkspaceAPI(t *testing.T) {
	cred, env := azuretest.NewCredential(t, "gcc-high")
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "management.usgovcloudapi.net", r.URL.Host)
		assert.Contains(t, r.URL.Path, "/providers/Microsoft.Synapse/workspaces/workspace/firewallRules")
		assert.Equal(t, "2021-06-01", r.URL.Query().Get("api-version"))
		return azuretest.JSON(r, `{"value":[{"properties":{"startIpAddress":"0.0.0.0","endIpAddress":"0.0.0.0"}}]}`), nil
	})
	found, err := checkFirewallRules(plugin.AzureEnricherConfig{Context: context.Background(), Credential: cred, Env: env}, "sub", "rg", "workspace", "Microsoft.Synapse/workspaces")
	require.NoError(t, err)
	assert.True(t, found)
}
