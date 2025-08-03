package azure

import (
	"encoding/json"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureContainerRegistrySecretsLink extracts secrets from Azure Container Registries
type AzureContainerRegistrySecretsLink struct {
	*chain.Base
}

func NewAzureContainerRegistrySecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureContainerRegistrySecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureContainerRegistrySecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureContainerRegistrySecretsLink) Process(resource *model.AzureResource) error {
	// For now, just scan the resource properties for potential secrets
	// This could be expanded to actually pull and scan container images
	// similar to the AWS ECR implementation

	l.Logger.Debug("Scanning container registry resource", "resource_id", resource.Key)

	if resource.Properties != nil {
		// Convert properties to JSON for scanning
		propsContent, err := json.Marshal(resource.Properties)
		if err == nil {
			npInput := jtypes.NPInput{
				Content: string(propsContent),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.ContainerRegistry/registries",
					ResourceID:   resource.Key,
					AccountID:    resource.AccountRef,
				},
			}
			l.Send(npInput)
		}
	}

	return nil
}
