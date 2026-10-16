package armenum

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

func TestRawPolicyPagesUseSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "usgovernment"} {
		t.Run(typ, func(t *testing.T) {
			cred, recorder := azuretest.NewCredential(t, typ)
			env := azurecloud.ForCredential(cred)
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, strings.TrimPrefix(env.ARM, "https://"), r.URL.Host)
				assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
				if calls == 1 {
					return azuretest.JSON(r, fmt.Sprintf(`{"value":[{"id":"one"}],"nextLink":%q}`, env.ARM+"/next")), nil
				}
				return azuretest.JSON(r, `{"value":[{"id":"two"}]}`), nil
			})
			pager, err := newRawPolicyPager("sub", cred)
			require.NoError(t, err)
			first, next, err := pager.nextPage(context.Background())
			require.NoError(t, err)
			require.Len(t, first, 1)
			require.NotEmpty(t, next)
			second, next, err := pager.nextPage(context.Background())
			require.NoError(t, err)
			require.Len(t, second, 1)
			assert.Empty(t, next)
			assert.Equal(t, 2, calls)
			assert.Equal(t, []string{env.ARMScope, env.ARMScope}, recorder.Scopes())
		})
	}
}

func TestRawPolicyRejectsUnsafeNextLinksAndRedirects(t *testing.T) {
	for _, target := range []string{"https://management.azure.com/exfil", "https://management.usgovcloudapi.net.evil/exfil", "https://evil@management.usgovcloudapi.net/exfil", "https://management.usgovcloudapi.net/exfil#fragment"} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", target, redirect), func(t *testing.T) {
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					resp := azuretest.JSON(r, fmt.Sprintf(`{"value":[],"nextLink":%q}`, target))
					if redirect {
						resp.StatusCode = 302
						resp.Header.Set("Location", target)
					}
					return resp, nil
				})
				cred, _ := azuretest.NewCredential(t, "usgovernment")
				pager, err := newRawPolicyPager("sub", cred)
				require.NoError(t, err)
				_, _, err = pager.nextPage(context.Background())
				require.Error(t, err)
				assert.Equal(t, 1, calls)
			})
		}
	}
}
