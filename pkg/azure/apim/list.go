package apim

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

const listAPIsRequestTimeout = 30 * time.Second

// Older API versions omit native MCP APIs from the list response.
const APIListAPIVersion = "2024-06-01-preview"

func ListAPIs(ctx context.Context, cred azcore.TokenCredential, env azurecloud.Environment, subscriptionID, resourceGroup, serviceName string) ([]APIInventoryItem, error) {
	return listAPIs(ctx, cred, subscriptionID, resourceGroup, serviceName, env.ARMClientOptions())
}

func listAPIs(ctx context.Context, cred azcore.TokenCredential, subscriptionID, resourceGroup, serviceName string, options *arm.ClientOptions) ([]APIInventoryItem, error) {
	options.APIVersion = APIListAPIVersion
	options.DisableRPRegistration = true
	options.Retry.MaxRetries = -1 // The existing paginator owns throttling retries.
	options.Retry.TryTimeout = listAPIsRequestTimeout
	client, err := armapimanagement.NewAPIClient(subscriptionID, cred, options)
	if err != nil {
		return nil, fmt.Errorf("create APIM API client: %w", err)
	}

	service, ok := options.Cloud.Services[cloud.ResourceManager]
	if !ok {
		service = cloud.AzurePublic.Services[cloud.ResourceManager]
	}
	base, err := url.Parse(service.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse ARM endpoint: %w", err)
	}

	pager := client.NewListByServicePager(resourceGroup, serviceName, nil)
	var all []APIInventoryItem
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false, err
		}
		if page.NextLink != nil && *page.NextLink != "" {
			if err := azurecloud.ValidateARMURL(*page.NextLink, base); err != nil {
				return false, err
			}
		}
		all = append(all, apiListResponseToItems(page.APICollection)...)
		return pager.More(), nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

func apiListResponseToItems(resp armapimanagement.APICollection) []APIInventoryItem {
	if len(resp.Value) == 0 {
		return nil
	}
	items := make([]APIInventoryItem, 0, len(resp.Value))
	for _, entry := range resp.Value {
		items = append(items, apiInventoryItem(entry))
	}
	return items
}

func apiInventoryItem(entry *armapimanagement.APIContract) APIInventoryItem {
	if entry == nil {
		return APIInventoryItem{}
	}
	item := APIInventoryItem{APIID: valueOf(entry.Name)}
	if entry.Properties == nil {
		return item
	}

	props := entry.Properties
	item.DisplayName = valueOf(props.DisplayName)
	item.Path = valueOf(props.Path)
	item.SubscriptionRequired = valueOf(props.SubscriptionRequired)
	item.IsMCPServer = strings.EqualFold(string(valueOf(props.APIType)), "mcp")
	if props.Protocols != nil {
		item.Protocols = make([]string, len(props.Protocols))
		for i, protocol := range props.Protocols {
			item.Protocols[i] = string(valueOf(protocol))
		}
	}
	return item
}

func valueOf[T any](p *T) (value T) {
	if p != nil {
		return *p
	}
	return value
}
