package azure

import (
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AzureFunctionAppSecretsLink extracts secrets from Azure Function Apps
// This is similar to web apps but with function-specific configurations
// TODO: Re-enable composition with AzureWebAppSecretsLink after it's migrated
type AzureFunctionAppSecretsLink struct {
	*base.NativeAzureLink
	// webAppLink *AzureWebAppSecretsLink // Disabled until webapp_secrets.go is migrated
}

func NewAzureFunctionAppSecretsLink(args map[string]any) *AzureFunctionAppSecretsLink {
	return &AzureFunctionAppSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("function-app-secrets", args),
	}
}

func (l *AzureFunctionAppSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[[]string]("subscription", "Azure subscription ID"),
	}
}

func (l *AzureFunctionAppSecretsLink) Process(resource *output.CloudResource) error {
	// TODO: Delegate to web app link once it's migrated
	// For now, return unimplemented error
	return nil // Placeholder until webapp_secrets.go is migrated
}
