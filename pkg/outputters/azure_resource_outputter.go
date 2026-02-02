package outputters

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/diocletian/internal/message"
	"github.com/praetorian-inc/diocletian/pkg/output"
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

	cloudResource, ok := v.(*output.CloudResource)
	if !ok {
		// Try without pointer in case it's passed as value
		if cloudResourceValue, ok := v.(output.CloudResource); ok {
			cloudResource = &cloudResourceValue
		} else {
			return nil // Not a CloudResource, silently ignore
		}
	}

	resourceInfo := cloudResource.ResourceID

	// Check for display name in properties
	if cloudResource.Properties != nil {
		if displayName, ok := cloudResource.Properties["displayName"].(string); ok && displayName != "" && displayName != cloudResource.ResourceID {
			resourceInfo = fmt.Sprintf("%s (%s)", resourceInfo, displayName)
		}
	}

	// Get additional information to display
	var additionalInfo []string

	// Check for IPs in properties
	if cloudResource.Properties != nil {
		if ips, ok := cloudResource.Properties["ips"].([]string); ok && len(ips) > 0 {
			for _, ip := range ips {
				if ip != "" {
					additionalInfo = append(additionalInfo, fmt.Sprintf("IP: %s", ip))
				}
			}
		}
		// Also check for single ip field
		if ip, ok := cloudResource.Properties["ip"].(string); ok && ip != "" {
			additionalInfo = append(additionalInfo, fmt.Sprintf("IP: %s", ip))
		}
	}

	// Check for URLs in properties
	if cloudResource.Properties != nil {
		if urls, ok := cloudResource.Properties["urls"].([]string); ok && len(urls) > 0 {
			for _, url := range urls {
				if url != "" {
					additionalInfo = append(additionalInfo, fmt.Sprintf("URL: %s", url))
				}
			}
		}
		// Also check for single url field
		if url, ok := cloudResource.Properties["url"].(string); ok && url != "" {
			additionalInfo = append(additionalInfo, fmt.Sprintf("URL: %s", url))
		}
	}

	// Add region if available
	if cloudResource.Region != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Region: %s", cloudResource.Region))
	}

	// Add resource group from properties if available
	if cloudResource.Properties != nil {
		if resourceGroup, ok := cloudResource.Properties["resourceGroup"].(string); ok && resourceGroup != "" {
			additionalInfo = append(additionalInfo, fmt.Sprintf("Resource Group: %s", resourceGroup))
		}
	}

	// Add resource type
	if cloudResource.ResourceType != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Type: %s", cloudResource.ResourceType))
	}

	// Check for public access indicator in properties
	if cloudResource.Properties != nil {
		if isPrivate, ok := cloudResource.Properties["isPrivate"].(bool); ok && !isPrivate {
			additionalInfo = append(additionalInfo, "Public Access: Yes")
		}
	}

	// Check for any template ID if it exists in properties
	if templateID := o.extractTemplateID(cloudResource); templateID != "" {
		additionalInfo = append(additionalInfo, fmt.Sprintf("Template: %s", templateID))
	}

	// Output the resource information
	o.outputResource(resourceInfo, additionalInfo)
	return nil
}

// extractTemplateID extracts the template ID from the resource properties if available
func (o *AzureResourceOutputter) extractTemplateID(cloudResource *output.CloudResource) string {
	if cloudResource.Properties == nil {
		return ""
	}

	if templateID, ok := cloudResource.Properties["templateID"].(string); ok {
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
