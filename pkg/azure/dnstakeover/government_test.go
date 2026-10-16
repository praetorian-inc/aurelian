package dnstakeover

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestDNSAvailabilityChecksRespectSelectedCloudAndSuffix(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		for _, service := range []string{"appservice", "blob", "trafficmanager"} {
			t.Run(typ+"/"+service, func(t *testing.T) {
				cred, recorder := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				suffix := env.AppServiceSuffix
				check := checkAppService
				switch service {
				case "blob":
					suffix = env.BlobSuffix
					check = checkBlobStorage
				case "trafficmanager":
					suffix = env.TrafficManagerSuffix
					check = checkTrafficManager
				}
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					assert.Equal(t, strings.TrimPrefix(env.ARM, "https://"), r.URL.Host)
					assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
					return azuretest.JSON(r, `{"nameAvailable":true}`), nil
				})
				ctx := CheckContext{Ctx: context.Background(), Credential: cred, SubscriptionID: "sub"}
				rec := AzureDNSRecord{Type: "CNAME", Values: []string{"unclaimed." + suffix}, FQDN: "www.example.test"}
				items, err := azuretest.Collect(func(out *pipeline.P[model.AurelianModel]) error { return check(ctx, rec, out) })
				require.NoError(t, err)
				assert.Len(t, items, 1)
				assert.Equal(t, 1, calls)
				assert.Equal(t, []string{env.ARMScope}, recorder.Scopes())
				// A similarly named domain is not a service suffix and must not trigger a lookup.
				rec.Values = []string{"unclaimed." + suffix + ".attacker"}
				_, err = azuretest.Collect(func(out *pipeline.P[model.AurelianModel]) error { return check(ctx, rec, out) })
				require.NoError(t, err)
				assert.Equal(t, 1, calls)
			})
		}
	}
}

func TestDNSAvailabilityFailuresRemainBestEffortAcrossClouds(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, service := range []string{"appservice", "blob", "trafficmanager"} {
			t.Run(typ+"/"+service, func(t *testing.T) {
				cred, _ := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				suffix := env.AppServiceSuffix
				switch service {
				case "blob":
					suffix = env.BlobSuffix
				case "trafficmanager":
					suffix = env.TrafficManagerSuffix
				}
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					resp := azuretest.JSON(r, `{"nameAvailable":true}`)
					if calls == 1 {
						resp = azuretest.JSON(r, `{"error":{"code":"ResourceNotFound","message":"offline"}}`)
						resp.StatusCode = http.StatusNotFound
					}
					return resp, nil
				})
				checker := NewDNSTakeoverChecker(context.Background(), plugin.AzureCommonRecon{AzureCredential: cred}, []string{"sub"})
				items, err := azuretest.Collect(func(out *pipeline.P[model.AurelianModel]) error {
					return checker.Check(AzureDNSRecord{SubscriptionID: "sub", Type: "CNAME", FQDN: "www.example.test", Values: []string{"failed." + suffix, "available." + suffix}}, out)
				})
				require.NoError(t, err)
				assert.Equal(t, 2, calls, "a failed lookup must not prevent the next lookup")
				assert.Len(t, items, 1)
			})
		}
	}
}

func TestDNSEnumerationFailuresRemainBestEffortAcrossClouds(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, stage := range []string{"zones", "records"} {
			t.Run(typ+"/"+stage, func(t *testing.T) {
				cred, _ := azuretest.NewCredential(t, typ)
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 && stage == "zones" || strings.Contains(r.URL.Path, "/dnsZones/failed/") {
						resp := azuretest.JSON(r, `{"error":{"code":"ResourceNotFound","message":"offline"}}`)
						resp.StatusCode = http.StatusNotFound
						return resp, nil
					}
					if calls == 1 {
						return azuretest.JSON(r, `{"value":[{"name":"failed","id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnsZones/failed"},{"name":"available","id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnsZones/available"}]}`), nil
					}
					return azuretest.JSON(r, `{"value":[{"name":"www","type":"Microsoft.Network/dnsZones/CNAME","properties":{"CNAMERecord":{"cname":"example.test"}}}]}`), nil
				})
				items, err := azuretest.Collect(func(out *pipeline.P[AzureDNSRecord]) error {
					return NewDNSEnumerator(cred).EnumerateSubscription("sub", out)
				})
				require.NoError(t, err)
				if stage == "zones" {
					assert.Empty(t, items)
					assert.Equal(t, 1, calls)
				} else {
					assert.Len(t, items, 1, "a failed zone must not prevent enumeration of other zones")
					assert.Equal(t, 3, calls)
				}
			})
		}
	}
}

func TestGovernmentDNSUnverifiedChecksStayGated(t *testing.T) {
	cred, _ := azuretest.NewCredential(t, "gcc-high")
	calls := 0
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unverified check must not send Government credentials")
	})
	checker := NewDNSTakeoverChecker(context.Background(), plugin.AzureCommonRecon{AzureCredential: cred}, []string{"sub"})
	for _, rec := range []AzureDNSRecord{
		{Type: "CNAME", Values: []string{"unclaimed.azureedge.net"}},
		{Type: "CNAME", Values: []string{"unclaimed.azurefd.net"}},
		{Type: "NS", Values: []string{"ns1-01.azure-dns.com"}},
	} {
		out := pipeline.New[model.AurelianModel]()
		require.NoError(t, checker.Check(rec, out))
		out.Close()
	}
	assert.Zero(t, calls)
}
