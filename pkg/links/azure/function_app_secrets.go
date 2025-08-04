package azure

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureFunctionAppSecretsLink extracts secrets from Azure Function Apps
// This is similar to web apps but with function-specific configurations
type AzureFunctionAppSecretsLink struct {
	*chain.Base
	webAppLink *AzureWebAppSecretsLink
}

func NewAzureFunctionAppSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureFunctionAppSecretsLink{}
	l.Base = chain.NewBase(l, configs...)

	// Reuse web app link functionality since function apps are built on the same platform
	l.webAppLink = &AzureWebAppSecretsLink{}
	l.webAppLink.Base = l.Base

	return l
}

func (l *AzureFunctionAppSecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureFunctionAppSecretsLink) Process(resource *model.AzureResource) error {
	// Function apps use the same API as web apps, so we can delegate
	// to the web app secrets link which already handles function app keys
	return l.webAppLink.Process(resource)
}
