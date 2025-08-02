package outputters

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureResourceOutputter outputs Azure resources to the console with formatted information
type AzureResourceOutputter struct {
	*chain.BaseOutputter
}

// NewAzureResourceOutputter creates a new console outputter for Azure resources
func NewAzureResourceOutputter(configs ...cfg.Config) chain.Outputter {
	o := &AzureResourceOutputter{}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output prints an Azure resource to the console
func (o *AzureResourceOutputter) Output(v any) error {
	// Check if we received a NamedOutputData structure
	if namedData, ok := v.(NamedOutputData); ok {
		// Extract the actual data from the NamedOutputData
		v = namedData.Data
	}

	azureResource, ok := v.(*model.AzureResource)
	if !ok {
		// Try without pointer in case it's passed as value
		if azureResourceValue, ok := v.(model.AzureResource); ok {
			azureResource = &azureResourceValue
		} else {
			return nil // Not an Azure resource, silently ignore
		}
	}

	resourceInfo := azureResource.Name

	// If we have a display name different from the key, show it
	if displayName := azureResource.GetDisplayName(); displayName != "" && displayName != azureResource.Name {
		resourceInfo = fmt.Sprintf("%s (%s)", resourceInfo, displayName)
	}

	// Get additional information to display
	var additionalInfo []string

	// Get IPs using the GetIPs method
	if ips := azureResource.GetIPs(); len(ips) > 0 {
		for _, ip := range ips {
			if ip != "" {
				additionalInfo = append(additionalInfo, fmt.Sprintf("IP: %s", ip))
			}
		}
	}

	// Get URL using the GetURL method
	if urls := azureResource.GetURLs(); len(urls) > 0 {
		for _, url := range urls {
			if url != "" {
				additionalInfo = append(additionalInfo, fmt.Sprintf("URL: %s", url))
			}
		}
	}

	// Add region if available
	if region := azureResource.GetRegion(); region != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Region: %s", region))
	}

	// Add resource group if available
	if resourceGroup := azureResource.GetResourceGroup(); resourceGroup != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Resource Group: %s", resourceGroup))
	}

	// Add resource type
	if string(azureResource.ResourceType) != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Type: %s", azureResource.ResourceType))
	}

	// Check if resource has public access (not private)
	if !azureResource.IsPrivate() {
		additionalInfo = append(additionalInfo, "Public Access: Yes")
	}

	// Check for any template ID if it exists in properties
	if templateID := o.extractTemplateID(azureResource); templateID != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Template: %s", templateID))
	}

	// Output the resource information
	o.outputResource(resourceInfo, additionalInfo)
	return nil
}

// extractTemplateID extracts the template ID from the resource properties if available
func (o *AzureResourceOutputter) extractTemplateID(azureResource *model.AzureResource) string {
	if azureResource.Properties == nil {
		return ""
	}

	if templateID, ok := azureResource.Properties["templateID"].(string); ok {
		return templateID
	}

	return ""
}

// outputResource handles the formatting of the resource output similar to ERD console outputter
func (o *AzureResourceOutputter) outputResource(resourceInfo string, additionalInfo []string) {
	if len(additionalInfo) > 0 {
		infoOut := strings.Join(additionalInfo, "\n    ")
		message.Success("%s\n    %s", resourceInfo, infoOut)
	} else {
		message.Success("%s", resourceInfo)
	}
}

// Initialize is called when the outputter is initialized
func (o *AzureResourceOutputter) Initialize() error {
	return nil
}

// Complete is called when the chain is complete
func (o *AzureResourceOutputter) Complete() error {
	return nil
}

// Params returns the parameters for this outputter
func (o *AzureResourceOutputter) Params() []cfg.Param {
	return []cfg.Param{
		// No additional parameters needed
	}
}
