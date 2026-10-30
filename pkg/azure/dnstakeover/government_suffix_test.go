package dnstakeover

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestDNSChecksUseSelectedCloudSuffix(t *testing.T) {
	for _, service := range []struct {
		name, publicSuffix, governmentSuffix string
		check                                checkerFunc
	}{
		{"appservice", ".azurewebsites.net", ".azurewebsites.us", checkAppService},
		{"blob", ".blob.core.windows.net", ".blob.core.usgovcloudapi.net", checkBlobStorage},
		{"trafficmanager", ".trafficmanager.net", ".usgovtrafficmanager.net", checkTrafficManager},
	} {
		for _, tc := range []struct {
			cloud, matching, other, scope string
		}{
			{"public", service.publicSuffix, service.governmentSuffix, "https://management.core.windows.net//.default"},
			{"gcc-high", service.governmentSuffix, service.publicSuffix, "https://management.core.usgovcloudapi.net//.default"},
		} {
			t.Run(service.name+"/"+tc.cloud, func(t *testing.T) {
				// Stop before HTTP; requesting a token proves the suffix matched.
				cred := &azuretest.Credential{Err: errors.New("offline")}
				ctx := CheckContext{Ctx: context.Background(), Env: azurecloud.Resolve(tc.cloud), Credential: cred, SubscriptionID: "sub"}
				require.NoError(t, service.check(ctx, AzureDNSRecord{Values: []string{
					"other" + tc.other, "lookalike" + tc.matching + ".example", strings.TrimPrefix(tc.matching, "."),
				}}, nil))
				assert.Empty(t, cred.Scopes)
				require.NoError(t, service.check(ctx, AzureDNSRecord{Values: []string{"site" + strings.ToUpper(tc.matching)}}, nil))
				assert.Equal(t, []string{tc.scope}, cred.Scopes)
			})
		}
	}
}
