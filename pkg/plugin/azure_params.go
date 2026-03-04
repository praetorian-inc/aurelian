package plugin

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	azureauth "github.com/praetorian-inc/aurelian/pkg/azure/auth"
)

// AzureCommonRecon contains common parameters for Azure reconnaissance modules.
type AzureCommonRecon struct {
	SubscriptionID  []string             `param:"subscription-id" desc:"Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions" required:"true" shortcode:"s"`
	AzureCredential azcore.TokenCredential `param:"-"`
}

func (c *AzureCommonRecon) PostBind(_ Config, _ Module) error {
	cred, err := azureauth.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}
	c.AzureCredential = cred
	return nil
}
