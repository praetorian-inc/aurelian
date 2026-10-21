package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

type azureModuleID struct {
	Module
	id string
}

func (m azureModuleID) ID() string { return m.id }

func TestAzureCloudBindingDefaultsAndSequentialReuse(t *testing.T) {
	var params AzureCommonRecon
	for _, args := range []map[string]any{
		{"cloud-type": "gcc-high"}, {}, {"cloud-type": "gcc-high"}, {"cloud-type": ""}, {"cloud-type": "public"}, {"cloud-type": "gcc-high"},
	} {
		previous := params.AzureCredential
		cfg := Config{Args: args}
		require.NoError(t, Bind(cfg, &params))
		require.NoError(t, params.PostBind(cfg, azureModuleID{id: "list-all"}))
		expected := "public"
		if args["cloud-type"] == "gcc-high" {
			expected = "gcc-high"
		}
		assert.Equal(t, expected, params.Environment.Name)
		if previous != nil {
			assert.NotSame(t, previous, params.AzureCredential, "new job must get a fresh token chain/cache")
		}
	}
}

func TestAzureGovernmentOnlyEnablesFiveVerifiedModulePaths(t *testing.T) {
	for _, id := range []string{"list-all", "configuration-scan", "public-resources", "find-secrets", "subdomain-takeover", "apim-audit", "conditional-access-policies", "unknown"} {
		params := AzureCommonRecon{AzureReconBase: AzureReconBase{CloudType: "gcc-high"}}
		err := params.PostBind(Config{}, azureModuleID{id: id})
		switch id {
		case "list-all", "configuration-scan", "public-resources", "find-secrets", "subdomain-takeover":
			require.NoError(t, err)
		default:
			require.ErrorContains(t, err, "not supported")
		}
	}
	params := AzureEntraRecon{AzureReconBase: AzureReconBase{CloudType: "gcc-high"}}
	require.ErrorContains(t, params.PostBind(Config{}, nil), "not supported")
	for _, value := range []string{"", "public"} {
		params.CloudType = value
		require.NoError(t, params.PostBind(Config{}, nil))
	}
	for _, value := range []string{"unexpected", "usgovernment"} {
		unknown := AzureCommonRecon{AzureReconBase: AzureReconBase{CloudType: value}}
		require.NoError(t, unknown.PostBind(Config{}, nil))
		assert.Equal(t, azurecloud.Public, unknown.Environment.Name)
		unknownEntra := AzureEntraRecon{AzureReconBase: AzureReconBase{CloudType: value}}
		require.NoError(t, unknownEntra.PostBind(Config{}, nil))
		assert.Equal(t, azurecloud.Public, unknownEntra.Environment.Name)
	}
}
