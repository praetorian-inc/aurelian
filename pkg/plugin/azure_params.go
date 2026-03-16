package plugin

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	azureauth "github.com/praetorian-inc/aurelian/pkg/azure/auth"
)

// AzureReconBase contains base parameters shared by all Azure recon modules.
type AzureReconBase struct {
	OutputDir string `param:"output-dir" desc:"Base output directory" default:"aurelian-output"`
}

// AzureCommonRecon contains common parameters for Azure reconnaissance modules.
type AzureCommonRecon struct {
	AzureReconBase
	Concurrency     int                    `param:"concurrency" desc:"Maximum concurrent API requests" default:"5"`
	SubscriptionIDs []string               `param:"subscription-ids" desc:"Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions" default:"all" shortcode:"s"`
	AzureCredential azcore.TokenCredential `param:"-"`
}

func (c *AzureCommonRecon) PostBind(_ Config, _ Module) error {
	cred, err := azureauth.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}
	c.AzureCredential = cred
	c.Concurrency = max(1, c.Concurrency)
	return nil
}
