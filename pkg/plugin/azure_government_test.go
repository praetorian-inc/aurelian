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

func TestAzureCloudBindingAndReuse(t *testing.T) {
	// Invalid ambient authority would fail credential construction without explicit Cloud.
	t.Setenv("AZURE_AUTHORITY_HOST", "http://invalid.example")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_CLIENT_SECRET", "offline-secret")
	var params AzureCommonRecon
	for _, args := range []map[string]any{
		{"cloud-type": "gcc-high"}, {}, {"cloud-type": "gcc-high"},
		{"cloud-type": ""}, {"cloud-type": "legacy"}, {"cloud-type": "public"},
	} {
		previous := params.AzureCredential
		cfg := Config{Args: args}
		require.NoError(t, Bind(cfg, &params))
		require.NoError(t, params.PostBind(cfg, azureModuleID{id: "list-all"}))
		want := azurecloud.Public
		if args["cloud-type"] == "gcc-high" {
			want = azurecloud.Government
		}
		assert.Equal(t, want, params.Env.Name)
		assert.GreaterOrEqual(t, params.Concurrency, 1)
		require.NotNil(t, params.AzureCredential)
		if previous != nil {
			assert.NotSame(t, previous, params.AzureCredential)
		}
	}
}

func TestAzureGovernmentModuleAllowlist(t *testing.T) {
	for _, id := range []string{"list-all", "configuration-scan", "public-resources", "find-secrets", "subdomain-takeover", "apim-audit", "unknown"} {
		t.Run(id, func(t *testing.T) {
			params := AzureCommonRecon{AzureReconBase: AzureReconBase{CloudType: "gcc-high"}}
			err := params.PostBind(Config{}, azureModuleID{id: id})
			switch id {
			case "apim-audit", "unknown":
				require.ErrorContains(t, err, "not supported")
				assert.Nil(t, params.AzureCredential)
			default:
				require.NoError(t, err)
			}
			params.CloudType = "public"
			require.NoError(t, params.PostBind(Config{}, azureModuleID{id: id}))
		})
	}
}

func TestAzureEntraRefusesGovernment(t *testing.T) {
	params := AzureEntraRecon{AzureReconBase: AzureReconBase{CloudType: "gcc-high"}}
	require.ErrorContains(t, params.PostBind(Config{}, nil), "not supported")
	assert.Nil(t, params.AzureCredential)
	for _, name := range []string{"", "public", "legacy"} {
		params.CloudType = name
		require.NoError(t, params.PostBind(Config{}, nil))
		assert.Equal(t, azurecloud.Public, params.Env.Name)
	}
}

func TestAzureCloudFlag(t *testing.T) {
	for _, params := range []any{&AzureCommonRecon{}, &AzureEntraRecon{}} {
		parameters, err := ParametersFrom(params)
		require.NoError(t, err)
		var cloudFlag *Parameter
		for i := range parameters {
			if parameters[i].Name == "cloud-type" {
				cloudFlag = &parameters[i]
			}
		}
		require.NotNil(t, cloudFlag)
		assert.Equal(t, "public", cloudFlag.Default)
		assert.Contains(t, cloudFlag.Description, "anything else defaults to public")
	}
}
