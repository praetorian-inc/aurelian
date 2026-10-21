package apim

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestListAPIsSelectedCloudAndBoundaries(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		for _, mode := range []string{"pages", "cross-cloud", "foreign-host"} {
			t.Run(typ+"/"+mode, func(t *testing.T) {
				cred, env := azuretest.NewCredential(t, typ)
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					assert.Equal(t, strings.TrimPrefix(env.ARMEndpoint(), "https://"), r.URL.Host)
					assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
					if calls > 1 {
						return azuretest.JSON(r, `{"value":[{"name":"two"}]}`), nil
					}
					target := env.ARMEndpoint() + "/next"
					switch mode {
					case "cross-cloud":
						target = "https://management.azure.com/exfil"
						if env.Name == "public" {
							target = "https://management.usgovcloudapi.net/exfil"
						}
					case "foreign-host":
						target = env.ARMEndpoint() + ".attacker/exfil"
					}
					resp := azuretest.JSON(r, fmt.Sprintf(`{"value":[{"name":"one"}],"nextLink":%q}`, target))
					return resp, nil
				})
				items, err := ListAPIs(context.Background(), cred, env, "sub", "rg", "apim")
				if mode == "pages" {
					require.NoError(t, err)
					assert.Len(t, items, 2)
					assert.Equal(t, 2, calls)
				} else {
					require.Error(t, err)
					assert.Equal(t, 1, calls)
				}
				assert.Equal(t, []string{env.ARMScope()}, cred.Scopes())
			})
		}
	}
}
