package apim

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestListAPIsSelectedCloudAndBoundaries(t *testing.T) {
	for _, typ := range []string{"", "public", "usgovernment"} {
		for _, mode := range []string{"pages", "cross-cloud", "foreign-host", "userinfo", "redirect"} {
			t.Run(typ+"/"+mode, func(t *testing.T) {
				cred, recorder := azuretest.NewCredential(t, typ)
				env := azurecloud.ForCredential(cred)
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					assert.Equal(t, strings.TrimPrefix(env.ARM, "https://"), r.URL.Host)
					assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
					if calls > 1 {
						return azuretest.JSON(r, `{"value":[{"name":"two"}]}`), nil
					}
					target := env.ARM + "/next"
					switch mode {
					case "cross-cloud":
						target = "https://management.azure.com/exfil"
						if env.Name == "public" {
							target = "https://management.usgovcloudapi.net/exfil"
						}
					case "foreign-host":
						target = env.ARM + ".attacker/exfil"
					case "userinfo":
						target = strings.Replace(env.ARM, "https://", "https://evil@", 1) + "/exfil"
					}
					resp := azuretest.JSON(r, fmt.Sprintf(`{"value":[{"name":"one"}],"nextLink":%q}`, target))
					if mode == "redirect" {
						resp.StatusCode = 302
						resp.Header.Set("Location", env.ARM[:8]+"child."+env.ARM[8:]+"/exfil")
					}
					return resp, nil
				})
				items, err := ListAPIs(context.Background(), cred, "sub", "rg", "apim")
				if mode == "pages" {
					require.NoError(t, err)
					assert.Len(t, items, 2)
					assert.Equal(t, 2, calls)
				} else {
					require.Error(t, err)
					assert.Equal(t, 1, calls)
				}
				assert.Equal(t, []string{env.ARMScope}, recorder.Scopes())
			})
		}
	}
}
