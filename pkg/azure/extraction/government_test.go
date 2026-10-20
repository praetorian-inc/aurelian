package extraction

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestExtractionDataPlanesSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		for _, service := range []string{"appconfig", "cosmos", "blob"} {
			t.Run(typ+"/"+service, func(t *testing.T) {
				cred, env := azuretest.NewCredential(t, typ)
				ctx := extractContext{Context: context.Background(), Cred: cred, Env: env}
				var mu sync.Mutex
				hosts := map[string]int{}
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					mu.Lock()
					hosts[r.URL.Host]++
					call := hosts[r.URL.Host]
					mu.Unlock()
					switch r.URL.Host {
					case strings.TrimPrefix(env.ARMEndpoint(), "https://"):
						assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
						assert.Equal(t, "blob", service, "Cosmos must not require an extra ARM endpoint lookup")
						return azuretest.JSON(r, fmt.Sprintf(`{"keys":[{"value":%q}]}`, base64.StdEncoding.EncodeToString([]byte("offline-storage-key")))), nil
					case "account." + env.BlobSuffix:
						assert.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "SharedKey account:"))
						resp := azuretest.JSON(r, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Containers/><NextMarker/></EnumerationResults>`)
						resp.Header.Set("Content-Type", "application/xml")
						return resp, nil
					case "store." + env.AppConfigSuffix:
						assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
						body := `{"items":[{"key":"setting","value":"offline-value"}]}`
						if call == 1 {
							body = `{"items":[{"key":"first","value":"offline-value"}],"@nextLink":"/kv?after=offline"}`
						}
						resp := azuretest.JSON(r, body)
						resp.Header.Set("Sync-Token", "offline=token;sn=1")
						return resp, nil
					case "account." + env.CosmosSuffix, "account-offline." + env.CosmosSuffix:
						assert.NotEmpty(t, r.Header.Get("Authorization")) // Cosmos wraps the bearer in its own wire format
						if r.URL.Path == "" || r.URL.Path == "/" {
							return azuretest.JSON(r, fmt.Sprintf(`{"id":"account","readableLocations":[{"name":"offline","databaseAccountEndpoint":%q}],"writableLocations":[{"name":"offline","databaseAccountEndpoint":%q}]}`, "https://account-offline."+env.CosmosSuffix, "https://account-offline."+env.CosmosSuffix)), nil
						}
						switch r.URL.Path {
						case "/dbs":
							return azuretest.JSON(r, `{"Databases":[{"id":"db"}],"_count":1}`), nil
						case "/dbs/db/colls":
							return azuretest.JSON(r, `{"DocumentCollections":[{"id":"settings"}],"_count":1}`), nil
						default:
							return azuretest.JSON(r, `{"Documents":[{"id":"config","setting":"offline-value"}],"_count":1}`), nil
						}
					default:
						return nil, fmt.Errorf("unexpected data-plane destination: %s", r.URL.Host)
					}
				})
				resource := output.AzureResource{SubscriptionID: "sub", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"}
				_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
					switch service {
					case "appconfig":
						return extractAppConfigKeyValues(ctx, resource, out)
					case "cosmos":
						resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account"
						return extractCosmosConfigDocs(ctx, resource, out)
					case "blob":
						resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"
						return extractStorageBlobs(ctx, resource, out)
					}
					return fmt.Errorf("unknown fixture service")
				})
				require.NoError(t, err)
				expectedHost := "store." + env.AppConfigSuffix
				if service == "cosmos" {
					expectedHost = "account." + env.CosmosSuffix
				}
				if service == "blob" {
					expectedHost = "account." + env.BlobSuffix
				}
				mu.Lock()
				assert.Greater(t, hosts[expectedHost], 0)
				if service == "cosmos" {
					assert.Zero(t, hosts[strings.TrimPrefix(env.ARMEndpoint(), "https://")])
				}
				mu.Unlock()
				scopes := cred.Scopes()
				if service == "appconfig" {
					expectedScope := "https://store." + env.AppConfigSuffix + "/.default"
					if typ == "gcc-high" {
						expectedScope = "https://appconfig.azure.us/.default"
					}
					assert.Equal(t, []string{expectedScope}, scopes)
				}
				if service == "cosmos" {
					assert.Contains(t, scopes, "https://account."+env.CosmosSuffix+"/.default")
				}
				if service == "blob" {
					assert.Contains(t, scopes, env.ARMScope())
				}
			})
		}
	}
}

func TestGovernmentControlPlaneExtractorsUseGovernmentSDKOptions(t *testing.T) {
	types := []string{
		"Microsoft.Compute/virtualMachines", "Microsoft.Compute/virtualMachineScaleSets",
		"Microsoft.ContainerInstance/containerGroups", "Microsoft.App/containerApps",
		"Microsoft.HybridCompute/machines", "Microsoft.Web/sites", "Microsoft.Web/staticSites",
		"Microsoft.Logic/workflows", "Microsoft.ApiManagement/service",
		"Microsoft.Automation/automationAccounts", "Microsoft.DataFactory/factories",
		"Microsoft.Synapse/workspaces", "Microsoft.ContainerRegistry/registries",
		"Microsoft.Insights/components", "Microsoft.Batch/batchAccounts",
		"Microsoft.Resources/templateSpecs", "Microsoft.Resources/deployments",
		"Microsoft.Authorization/policyDefinitions",
	}
	for _, resourceType := range types {
		t.Run(resourceType, func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, "gcc-high")
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, "management.usgovcloudapi.net", r.URL.Host)
				assert.Equal(t, "Bearer offline-gcc-high", r.Header.Get("Authorization"))
				return azuretest.JSON(r, `{"value":[]}`), nil
			})
			_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
				return NewAzureExtractor(cred, env).Extract(output.AzureResource{SubscriptionID: "sub", ResourceType: resourceType, ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/" + resourceType + "/resource"}, out)
			})
			require.NoError(t, err)
			assert.Greater(t, calls, 0, "must exercise the extractor's SDK client")
			for _, scope := range cred.Scopes() {
				assert.Equal(t, env.ARMScope(), scope)
			}
		})
	}
}

func TestRunbookRawRequestUsesSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		t.Run(typ, func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, typ)
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, strings.TrimPrefix(env.ARMEndpoint(), "https://"), r.URL.Host)
				assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
				return azuretest.JSON(r, "offline runbook"), nil
			})
			body, err := fetchRunbookContent(extractContext{Context: context.Background(), Cred: cred, Env: env}, "sub", "rg", "account", "runbook")
			require.NoError(t, err)
			assert.Equal(t, "offline runbook", string(body))
			assert.Equal(t, 1, calls)
			assert.Equal(t, []string{env.ARMScope()}, cred.Scopes())
		})
	}
}

func TestBootDiagnosticsUsesServiceReturnedURL(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, mode := range []string{"direct", "https-redirect", "http-redirect"} {
			t.Run(typ+"/"+mode, func(t *testing.T) {
				cred, env := azuretest.NewCredential(t, typ)
				downloads := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					if r.URL.Host == strings.TrimPrefix(env.ARMEndpoint(), "https://") {
						return azuretest.JSON(r, `{"serialConsoleLogBlobUri":"https://service-returned.example/log?sig=offline"}`), nil
					}
					downloads++
					assert.Empty(t, r.Header.Get("Authorization"), "SAS download must not receive an ARM bearer token")
					resp := azuretest.JSON(r, "offline log")
					if downloads == 1 && mode != "direct" {
						resp.StatusCode = http.StatusFound
						scheme := "https"
						if mode == "http-redirect" {
							scheme = "http"
						}
						resp.Header.Set("Location", scheme+"://redirected.example/log?sig=offline")
					}
					return resp, nil
				})
				items, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
					return extractVMBootDiag(extractContext{Context: context.Background(), Cred: cred, Env: env}, output.AzureResource{SubscriptionID: "sub", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"}, out)
				})
				if mode == "http-redirect" {
					require.NoError(t, err)
					assert.Empty(t, items)
					assert.Equal(t, 1, downloads, "retain the pre-existing HTTPS downgrade check")
				} else {
					require.NoError(t, err)
					assert.Len(t, items, 1)
					expected := 1
					if mode == "https-redirect" {
						expected = 2
					}
					assert.Equal(t, expected, downloads)
				}
			})
		}
	}
}

func TestExtractionFailuresRemainBestEffortAcrossClouds(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusTeapot} {
			t.Run(fmt.Sprintf("%s/%d", typ, status), func(t *testing.T) {
				cred, env := azuretest.NewCredential(t, typ)
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					resp := azuretest.JSON(r, `{"error":{"code":"OfflineFailure","message":"offline unavailable service"}}`)
					resp.StatusCode = status
					return resp, nil
				})
				items, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
					return NewAzureExtractor(cred, env).Extract(output.AzureResource{SubscriptionID: "sub", ResourceType: "Microsoft.Web/sites", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/site", Tags: map[string]string{"setting": "offline-value"}}, out)
				})
				require.NoError(t, err)
				assert.Len(t, items, 1, "tag extraction must continue after API failures")
			})
		}
	}
}

func TestCosmosNestedFailuresRemainBestEffortAcrossClouds(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, stage := range []string{"containers", "documents"} {
			t.Run(typ+"/"+stage, func(t *testing.T) {
				cred, env := azuretest.NewCredential(t, typ)
				failed := false
				var mu sync.Mutex
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "" || r.URL.Path == "/" {
						return azuretest.JSON(r, `{"id":"account","readableLocations":[],"writableLocations":[]}`), nil
					}
					if r.URL.Path == "/dbs" {
						return azuretest.JSON(r, `{"Databases":[{"id":"db"}],"_count":1}`), nil
					}
					if r.URL.Path == "/dbs/db/colls" && stage != "containers" {
						return azuretest.JSON(r, `{"DocumentCollections":[{"id":"settings"}],"_count":1}`), nil
					}
					mu.Lock()
					failed = true
					mu.Unlock()
					resp := azuretest.JSON(r, `{"code":"NotFound","message":"offline unavailable"}`)
					resp.StatusCode = http.StatusNotFound
					return resp, nil
				})
				items, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
					return extractCosmosConfigDocs(extractContext{Context: context.Background(), Cred: cred, Env: env}, output.AzureResource{ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account"}, out)
				})
				require.NoError(t, err)
				assert.Empty(t, items)
				mu.Lock()
				assert.True(t, failed, "fixture must exercise the nested failure")
				mu.Unlock()
			})
		}
	}
}

func TestGovernmentUnsupportedExtractorsDoNotAbortPipeline(t *testing.T) {
	for _, concurrency := range []int{1, 3} {
		t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, "gcc-high")
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, "store.azconfig.azure.us", r.URL.Host, "unsupported resources must not make network requests")
				resp := azuretest.JSON(r, `{"items":[{"key":"setting","value":"offline-value"}]}`)
				resp.Header.Set("Sync-Token", "offline=token;sn=1")
				return resp, nil
			})
			resources := []output.AzureResource{
				{ResourceType: "Microsoft.DigitalTwins/digitalTwinsInstances", Tags: map[string]string{"setting": "offline-value"}},
				{ResourceType: "Microsoft.Blueprint/blueprints", Tags: map[string]string{"setting": "offline-value"}},
				{ResourceType: "Microsoft.AppConfiguration/configurationStores", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"},
			}
			extractor := NewAzureExtractor(cred, env)
			out := pipeline.New[output.ScanInput]()
			pipeline.Pipe(pipeline.From(resources...), extractor.Extract, out, &pipeline.PipeOpts{Concurrency: concurrency})
			items, err := out.Collect()
			require.NoError(t, err)
			assert.Len(t, items, 3, "unsupported service extraction must not suppress tags or later supported resources")
			assert.Equal(t, 1, calls)
			assert.Equal(t, []string{"https://appconfig.azure.us/.default"}, cred.Scopes())
		})
	}
}

func TestGovernmentUnsupportedExtractorsAreExplicitWithoutNetwork(t *testing.T) {
	cred, env := azuretest.NewCredential(t, "gcc-high")
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		t.Error("unsupported service must not authenticate or make HTTP requests")
		return nil, fmt.Errorf("offline")
	})
	for _, resourceType := range []string{"Microsoft.DigitalTwins/digitalTwinsInstances", "Microsoft.Blueprint/blueprints"} {
		out := pipeline.New[output.ScanInput]()
		err := NewAzureExtractor(cred, env).Extract(output.AzureResource{ResourceType: resourceType}, out)
		require.NoError(t, err)
		out.Close()
	}
}

func TestUnsupportedExtractorsPerCloud(t *testing.T) {
	_, public := azuretest.NewCredential(t, "public")
	_, gov := azuretest.NewCredential(t, "gcc-high")
	assert.Empty(t, unsupportedExtractors(public))
	assert.ElementsMatch(t, []string{"digitaltwins-properties", "blueprint-artifacts"}, unsupportedExtractors(gov))
}
