package armenum

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

func TestRawPolicyPagesUseSelectedCloud(t *testing.T) {
	for _, typ := range []string{"", "public", "gcc-high"} {
		t.Run(typ, func(t *testing.T) {
			cred, env := azuretest.NewCredential(t, typ)
			calls := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, strings.TrimPrefix(env.ARMEndpoint(), "https://"), r.URL.Host)
				assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
				if calls == 1 {
					return azuretest.JSON(r, fmt.Sprintf(`{"value":[{"id":"one"}],"nextLink":%q}`, env.ARMEndpoint()+"/next")), nil
				}
				return azuretest.JSON(r, `{"value":[{"id":"two"}]}`), nil
			})
			pager, err := newRawPolicyPager("sub", cred, env)
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
			assert.Equal(t, []string{env.ARMScope(), env.ARMScope()}, cred.Scopes())
		})
	}
}

func TestRawPolicyRejectsForeignNextLinks(t *testing.T) {
	for _, typ := range []string{"public", "gcc-high"} {
		for _, target := range []string{"https://foreign.invalid/next", "https://management.usgovcloudapi.net.evil/next"} {
			t.Run(typ+"/"+target, func(t *testing.T) {
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					return azuretest.JSON(r, fmt.Sprintf(`{"value":[],"nextLink":%q}`, target)), nil
				})
				cred, env := azuretest.NewCredential(t, typ)
				pager, err := newRawPolicyPager("sub", cred, env)
				require.NoError(t, err)
				_, _, err = pager.nextPage(context.Background())
				require.ErrorContains(t, err, "unexpected nextLink host")
				assert.Equal(t, 1, calls)
			})
		}
	}
}
