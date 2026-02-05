package azure

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureContainerRegistrySecretsLink extracts secrets from Azure Container Registries
type AzureContainerRegistrySecretsLink struct {
	*base.NativeAzureLink
}

func NewAzureContainerRegistrySecretsLink(args map[string]any) *AzureContainerRegistrySecretsLink {
	return &AzureContainerRegistrySecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("container-registry-secrets", args),
	}
}

func (l *AzureContainerRegistrySecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[[]string]("subscription", "Azure subscription ID"),
	}
}

func (l *AzureContainerRegistrySecretsLink) Process(resource *output.CloudResource) error {
	// For now, just scan the resource properties for potential secrets
	// This could be expanded to actually pull and scan container images
	// similar to the AWS ECR implementation

	l.Logger().Debug("Scanning container registry resource", "resource_id", resource.ResourceID)

	if resource.Properties != nil {
		// Convert properties to JSON for scanning
		propsContent, err := json.Marshal(resource.Properties)
		if err == nil {
			npInput := types.NpInput{
				Content: string(propsContent),
				Provenance: types.NpProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.ContainerRegistry/registries",
					ResourceID:   resource.ResourceID,
					AccountID:    resource.AccountRef,
				},
			}
			l.Send(npInput)
		}
	}

	return nil
}
