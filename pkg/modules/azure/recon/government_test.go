package recon

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/evaluators"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

// Exercise the actual five module pipelines, not just endpoint configuration.
// Default/empty/public compatibility and the Government path share the fixture.
func TestAzureRegisteredModuleIsolationBothOrdersAndConcurrent(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_CLIENT_SECRET", "offline-test-secret")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "login.microsoftonline.com", "login.microsoftonline.us":
			authority := "https://" + r.URL.Host
			if strings.Contains(r.URL.Path, ".well-known") {
				return azuretest.JSON(r, fmt.Sprintf(`{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`, authority+"/tenant/oauth2/v2.0/authorize", authority+"/tenant/oauth2/v2.0/token", authority+"/tenant/v2.0")), nil
			}
			token := "public"
			if strings.HasSuffix(r.URL.Host, ".us") {
				token = "gcc-high"
			}
			return azuretest.JSON(r, fmt.Sprintf(`{"access_token":%q,"expires_in":3600,"token_type":"Bearer"}`, "offline-"+token)), nil
		case "management.azure.com", "management.usgovcloudapi.net":
			typ := "public"
			if r.URL.Host == "management.usgovcloudapi.net" {
				typ = "gcc-high"
			}
			assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
			if strings.Contains(r.URL.Path, "Microsoft.ResourceGraph") {
				return azuretest.JSON(r, `{"data":[],"count":0,"totalRecords":0}`), nil
			}
			return azuretest.JSON(r, `{"subscriptionId":"00000000-0000-0000-0000-000000000001"}`), nil
		default:
			return nil, fmt.Errorf("unexpected offline isolation destination: %s", r.URL.Host)
		}
	})
	prototype := &AzureListAllResourcesModule{}
	wrapper := &plugin.ModuleWrapper{Module: prototype}
	run := func(typ string) {
		args := map[string]any{"subscription-ids": []string{"00000000-0000-0000-0000-000000000001"}}
		if typ != "omitted" {
			args["cloud-type"] = typ
		}
		out := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(pipeline.From(plugin.Config{Args: args, Context: context.Background()}), wrapper.Run, out)
		_, err := out.Collect()
		assert.NoError(t, err)
	}
	for _, order := range [][]string{{"public", "gcc-high", "omitted"}, {"gcc-high", "public", ""}} {
		for _, typ := range order {
			run(typ)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		for _, typ := range []string{"public", "gcc-high", "omitted"} {
			wg.Add(1)
			go func() { defer wg.Done(); run(typ) }()
		}
	}
	wg.Wait()
	assert.Empty(t, prototype.CloudType)
	assert.Nil(t, prototype.AzureCredential, "registry prototype must not retain job credentials")
}

func TestFiveAzureCapabilitiesSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		for _, id := range []string{"list-all", "configuration-scan", "public-resources", "find-secrets", "subdomain-takeover"} {
			t.Run(typ+"/"+id, func(t *testing.T) {
				const sub = "00000000-0000-0000-0000-000000000001"
				resourceID := "/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Web/sites/site"
				cred, recorder := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				var mu sync.Mutex
				requests := map[string]int{}
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					mu.Lock()
					requests[r.URL.Path]++
					mu.Unlock()
					if r.URL.Host != strings.TrimPrefix(env.ARM, "https://") {
						return nil, fmt.Errorf("wrong cloud host: %s", r.URL.Host)
					}
					assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
					path := strings.ToLower(r.URL.Path)
					switch {
					case path == "/subscriptions/"+sub:
						return azuretest.JSON(r, fmt.Sprintf(`{"subscriptionId":%q,"tenantId":"tenant-not-subscription","displayName":"offline"}`, sub)), nil
					case strings.Contains(path, "microsoft.resourcegraph/resources"):
						return azuretest.JSON(r, fmt.Sprintf(`{"data":[{"id":%q,"name":"site","type":"microsoft.web/sites","location":"usgovvirginia","properties":{}}],"count":1,"totalRecords":1}`, resourceID)), nil
					case strings.HasSuffix(path, "/dnszones"):
						return azuretest.JSON(r, fmt.Sprintf(`{"value":[{"name":"example.test","id":"/subscriptions/%s/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.test"}]}`, sub)), nil
					case strings.HasSuffix(path, "/recordsets"):
						return azuretest.JSON(r, fmt.Sprintf(`{"value":[{"name":"www","type":"Microsoft.Network/dnszones/CNAME","properties":{"fqdn":"www.example.test.","CNAMERecord":{"cname":"unclaimed.%s."}}}]}`, env.AppServiceSuffix)), nil
					case strings.HasSuffix(path, "/checknameavailability"):
						return azuretest.JSON(r, `{"nameAvailable":true}`), nil
					case strings.HasSuffix(path, "/authsettingsv2/list"):
						return azuretest.JSON(r, `{"properties":{"platform":{"enabled":false}}}`), nil
					case strings.HasSuffix(path, "/functions"):
						return azuretest.JSON(r, `{"value":[]}`), nil
					case strings.Contains(path, "/sites/site/"):
						return azuretest.JSON(r, `{"properties":{}}`), nil
					default:
						return nil, fmt.Errorf("unexpected offline capability request: %s", r.URL.Path)
					}
				})
				cfg := plugin.Config{Args: map[string]any{"cloud-type": typ, "subscription-ids": []string{sub}, "output-dir": t.TempDir()}, Context: context.Background(), Log: plugin.DiscardLogger()}
				var module plugin.Module
				switch id {
				case "list-all":
					m := &AzureListAllResourcesModule{}
					require.NoError(t, plugin.Bind(cfg, m.Parameters()))
					m.AzureCredential = cred
					module = m
				case "configuration-scan":
					m := &AzureConfigurationScanModule{}
					require.NoError(t, plugin.Bind(cfg, m.Parameters()))
					m.AzureCredential = cred
					module = m
				case "public-resources":
					m := &AzurePublicResourcesModule{}
					require.NoError(t, plugin.Bind(cfg, m.Parameters()))
					m.AzureCredential = cred
					module = m
				case "find-secrets":
					m := &AzureFindSecretsModule{}
					cfg.Args["resource-id"] = []string{resourceID}
					require.NoError(t, plugin.Bind(cfg, m.Parameters()))
					m.AzureCredential = cred
					module = m
				case "subdomain-takeover":
					m := &AzureSubdomainTakeoverModule{}
					require.NoError(t, plugin.Bind(cfg, m.Parameters()))
					m.AzureCredential = cred
					module = m
				}
				out := pipeline.New[model.AurelianModel]()
				pipeline.Pipe(pipeline.From(cfg), module.Run, out)
				results, err := out.Collect()
				require.NoError(t, err)
				if id != "find-secrets" {
					assert.NotEmpty(t, results)
				}
				mu.Lock()
				defer mu.Unlock()
				assert.NotEmpty(t, requests)
				if id == "configuration-scan" {
					authRequests := 0
					for path, count := range requests {
						if strings.EqualFold(path, resourceID+"/config/authsettingsV2/list") {
							authRequests += count
						}
					}
					assert.Greater(t, authRequests, 0, "configuration enrichers must use Government SDK clients too: %v", requests)
				}
				for _, scope := range recorder.Scopes() {
					assert.Equal(t, env.ARMScope, scope)
				}
			})
		}
	}
}
