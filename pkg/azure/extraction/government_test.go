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

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestExtractionDataPlanesSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "usgovernment"} {
		for _, service := range []string{"appconfig", "cosmos", "blob"} {
			t.Run(typ+"/"+service, func(t *testing.T) {
				cred, recorder := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				ctx := extractContext{Context: context.Background(), Cred: cred}
				var mu sync.Mutex
				hosts := map[string]int{}
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					mu.Lock()
					hosts[r.URL.Host]++
					call := hosts[r.URL.Host]
					mu.Unlock()
					switch r.URL.Host {
					case strings.TrimPrefix(env.ARM, "https://"):
						assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
						if service == "cosmos" {
							return azuretest.JSON(r, fmt.Sprintf(`{"properties":{"readLocations":[{"documentEndpoint":%q}],"writeLocations":[{"documentEndpoint":%q}]}}`, "https://account-offline."+env.CosmosSuffix, "https://account-offline."+env.CosmosSuffix)), nil
						}
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
				mu.Unlock()
				scopes := recorder.Scopes()
				if service == "appconfig" {
					assert.Contains(t, scopes, "https://store."+env.AppConfigSuffix+"/.default")
				}
				if service == "cosmos" {
					assert.Contains(t, scopes, "https://account."+env.CosmosSuffix+"/.default")
				}
				if service == "blob" {
					assert.Contains(t, scopes, env.ARMScope)
				}
			})
		}
	}
}

func TestDataPlanePaginationAndDiscoveryCannotChangeTokenOrigin(t *testing.T) {
	for _, service := range []string{"appconfig", "appconfig-header", "cosmos"} {
		t.Run(service, func(t *testing.T) {
			cred, _ := azuretest.NewCredential(t, "usgovernment")
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "management.usgovcloudapi.net" {
					return azuretest.JSON(r, `{"properties":{"readLocations":[{"documentEndpoint":"https://account.documents.azure.us"}]}}`), nil
				}
				calls++
				if strings.HasPrefix(service, "appconfig") {
					assert.Equal(t, "store.azconfig.azure.us", r.URL.Host)
					resp := azuretest.JSON(r, `{"items":[],"@nextLink":"https://store.azconfig.io/kv"}`)
					resp.Header.Set("Sync-Token", "offline=token;sn=1")
					if service == "appconfig-header" {
						resp = azuretest.JSON(r, `{"items":[]}`)
						resp.Header.Set("Sync-Token", "offline=token;sn=1")
						resp.Header.Set("Link", "<https://store.azconfig.io/kv>; rel=next")
					}
					return resp, nil
				}
				assert.Equal(t, "account.documents.azure.us", r.URL.Host)
				// Even SDK-discovered locations are not permission to send this account's
				// token to another cloud or an unvalidated regional origin.
				return azuretest.JSON(r, `{"id":"account","readableLocations":[{"name":"offline","databaseAccountEndpoint":"https://account.documents.azure.com"}],"writableLocations":[{"name":"offline","databaseAccountEndpoint":"https://account.documents.azure.com"}]}`), nil
			})
			_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
				ctx := extractContext{Context: context.Background(), Cred: cred}
				resource := output.AzureResource{SubscriptionID: "sub"}
				if strings.HasPrefix(service, "appconfig") {
					resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"
					return extractAppConfigKeyValues(ctx, resource, out)
				}
				resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account"
				return extractCosmosConfigDocs(ctx, resource, out)
			})
			require.Error(t, err)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestDataPlaneRedirectsDoNotForwardCredentials(t *testing.T) {
	for _, service := range []string{"appconfig", "cosmos", "blob"} {
		t.Run(service, func(t *testing.T) {
			cred, _ := azuretest.NewCredential(t, "usgovernment")
			ctx := extractContext{Context: context.Background(), Cred: cred}
			requests := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "management.usgovcloudapi.net" {
					if service == "cosmos" {
						return azuretest.JSON(r, `{"properties":{"readLocations":[{"documentEndpoint":"https://account.documents.azure.us"}]}}`), nil
					}
					return azuretest.JSON(r, fmt.Sprintf(`{"keys":[{"value":%q}]}`, base64.StdEncoding.EncodeToString([]byte("offline-storage-key")))), nil
				}
				if service == "cosmos" && (r.URL.Path == "" || r.URL.Path == "/") {
					return azuretest.JSON(r, `{"id":"account","readableLocations":[{"name":"offline","databaseAccountEndpoint":"https://account.documents.azure.us"}],"writableLocations":[{"name":"offline","databaseAccountEndpoint":"https://account.documents.azure.us"}]}`), nil
				}
				requests++
				expectedHost := "store.azconfig.azure.us"
				if service == "cosmos" {
					expectedHost = "account.documents.azure.us"
				}
				if service == "blob" {
					expectedHost = "account.blob.core.usgovcloudapi.net"
				}
				assert.Equal(t, expectedHost, r.URL.Host, "redirect destination must never be reached")
				resp := azuretest.JSON(r, "")
				resp.StatusCode = http.StatusFound
				resp.Header.Set("Location", "https://child."+r.URL.Host+"/exfil")
				return resp, nil
			})
			_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
				resource := output.AzureResource{SubscriptionID: "sub"}
				switch service {
				case "appconfig":
					resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"
					return extractAppConfigKeyValues(ctx, resource, out)
				case "cosmos":
					resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account"
					return extractCosmosConfigDocs(ctx, resource, out)
				case "blob":
					resource.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"
					return extractStorageBlobs(ctx, resource, out)
				}
				return nil
			})
			require.Error(t, err)
			assert.GreaterOrEqual(t, requests, 1) // SDK retries may repeat only the original origin
		})
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
			cred, recorder := azuretest.NewCredential(t, "usgovernment")
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, "management.usgovcloudapi.net", r.URL.Host)
				assert.Equal(t, "Bearer offline-usgovernment", r.Header.Get("Authorization"))
				return azuretest.JSON(r, `{"value":[]}`), nil
			})
			_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
				return NewAzureExtractor(cred).Extract(output.AzureResource{SubscriptionID: "sub", ResourceType: resourceType, ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/" + resourceType + "/resource"}, out)
			})
			require.NoError(t, err)
			assert.Greater(t, calls, 0, "must exercise the extractor's SDK client")
			for _, scope := range recorder.Scopes() {
				assert.Equal(t, "https://management.core.usgovcloudapi.net/.default", scope)
			}
		})
	}
}

func TestRunbookRawRequestCloudAndRedirectBoundary(t *testing.T) {
	for _, typ := range []string{"", "public", "usgovernment"} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", typ, redirect), func(t *testing.T) {
				cred, recorder := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					assert.Equal(t, strings.TrimPrefix(env.ARM, "https://"), r.URL.Host)
					assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
					resp := azuretest.JSON(r, "offline runbook")
					if redirect {
						resp.StatusCode = 302
						resp.Header.Set("Location", "https://child."+r.URL.Host+"/exfil")
					}
					return resp, nil
				})
				body, err := fetchRunbookContent(extractContext{Context: context.Background(), Cred: cred}, "sub", "rg", "account", "runbook")
				if redirect {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.Equal(t, "offline runbook", string(body))
				}
				assert.Equal(t, 1, calls)
				assert.Equal(t, []string{env.ARMScope}, recorder.Scopes())
			})
		}
	}
}

func TestBootDiagnosticsDownloadsStayInSelectedStorageCloud(t *testing.T) {
	for _, typ := range []string{"public", "usgovernment"} {
		for _, mode := range []string{"valid", "cross-cloud", "redirect"} {
			t.Run(typ+"/"+mode, func(t *testing.T) {
				cred, _ := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				downloads := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					if r.URL.Host == strings.TrimPrefix(env.ARM, "https://") {
						suffix := env.BlobSuffix
						if mode == "cross-cloud" {
							suffix = "blob.core.windows.net"
							if typ == "public" {
								suffix = "blob.core.usgovcloudapi.net"
							}
						}
						return azuretest.JSON(r, fmt.Sprintf(`{"serialConsoleLogBlobUri":"https://managed.%s/log?sig=offline"}`, suffix)), nil
					}
					downloads++
					assert.Equal(t, "managed."+env.BlobSuffix, r.URL.Host)
					assert.Empty(t, r.Header.Get("Authorization"), "SAS download must not receive an ARM bearer token")
					resp := azuretest.JSON(r, "offline log")
					if mode == "redirect" {
						resp.StatusCode = 302
						resp.Header.Set("Location", "https://attacker.invalid/exfil")
					}
					return resp, nil
				})
				items, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
					return extractVMBootDiag(extractContext{Context: context.Background(), Cred: cred}, output.AzureResource{SubscriptionID: "sub", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"}, out)
				})
				if mode == "cross-cloud" {
					require.Error(t, err)
					assert.Zero(t, downloads)
				} else {
					if mode == "redirect" && typ == "usgovernment" {
						require.ErrorContains(t, err, "incomplete")
					} else {
						require.NoError(t, err)
					}
					assert.Equal(t, 1, downloads)
				}
				if mode == "valid" {
					assert.Len(t, items, 1)
				} else {
					assert.Empty(t, items)
				}
			})
		}
	}
}

func TestGovernmentExtractionFailuresAreNotCleanResults(t *testing.T) {
	for _, typ := range []string{"public", "usgovernment"} {
		t.Run(typ, func(t *testing.T) {
			cred, _ := azuretest.NewCredential(t, typ)
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				resp := azuretest.JSON(r, `{"error":{"code":"ResourceNotFound","message":"offline unavailable service"}}`)
				resp.StatusCode = 404
				return resp, nil
			})
			_, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
				return NewAzureExtractor(cred).Extract(output.AzureResource{SubscriptionID: "sub", ResourceType: "Microsoft.Web/sites", ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/site"}, out)
			})
			if typ == "usgovernment" {
				require.ErrorContains(t, err, "incomplete")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGovernmentUnsupportedExtractorsAreExplicitWithoutNetwork(t *testing.T) {
	cred, _ := azuretest.NewCredential(t, "usgovernment")
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		t.Error("unsupported service must not authenticate or make HTTP requests")
		return nil, fmt.Errorf("offline")
	})
	for _, resourceType := range []string{"Microsoft.DigitalTwins/digitalTwinsInstances", "Microsoft.Blueprint/blueprints"} {
		out := pipeline.New[output.ScanInput]()
		err := NewAzureExtractor(cred).Extract(output.AzureResource{ResourceType: resourceType}, out)
		require.ErrorContains(t, err, "unsupported")
		out.Close()
	}
}
