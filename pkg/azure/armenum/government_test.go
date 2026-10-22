package armenum

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestGovernmentSkipsBlueprintEnumeration(t *testing.T) {
	for _, name := range []string{azurecloud.Public, azurecloud.Government} {
		t.Run(name, func(t *testing.T) {
			cred := &azuretest.Credential{Err: errors.New("offline")}
			enumerator := NewARMEnumerator(cred, azurecloud.Resolve(name))
			err := enumerator.listBlueprints(azuretypes.SubscriptionInfo{ID: "sub"}, nil)
			if name == azurecloud.Government {
				require.NoError(t, err)
				assert.Empty(t, cred.Scopes)
				return
			}
			require.ErrorContains(t, err, "offline")
			assert.Equal(t, []string{"https://management.core.windows.net//.default"}, cred.Scopes)
		})
	}
}
