package azurecloud

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// AppConfigCredential supplies the service audience when the cloud requires it.
// azappconfig v1.2 derives scopes from the store URL and has no audience option.
func (e Environment) AppConfigCredential(cred azcore.TokenCredential) azcore.TokenCredential {
	if e.AppConfigAudience == "" {
		return cred
	}
	return appConfigCredential{TokenCredential: cred, scope: e.AppConfigAudience + "/.default"}
}

type appConfigCredential struct {
	azcore.TokenCredential
	scope string
}

func (c appConfigCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	options.Scopes = []string{c.scope}
	return c.TokenCredential.GetToken(ctx, options)
}
