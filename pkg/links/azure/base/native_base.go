// pkg/links/azure/base/native_base.go
package base

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// NativeAzureLink is the base for all Azure links
type NativeAzureLink struct {
	*plugin.BaseLink
	SubscriptionID string
	TenantID       string
}

func NewNativeAzureLink(name string, args map[string]any) *NativeAzureLink {
	base := plugin.NewBaseLink(name, args)
	return &NativeAzureLink{
		BaseLink:       base,
		SubscriptionID: base.ArgString("subscription", ""),
		TenantID:       base.ArgString("tenant", ""),
	}
}

// GetCredential returns Azure default credential
func (l *NativeAzureLink) GetCredential() (*azidentity.DefaultAzureCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// StandardAzureParams returns common Azure parameters
func StandardAzureParams() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("subscription", "Azure subscription ID"),
		plugin.NewParam[string]("tenant", "Azure tenant ID"),
	}
}
