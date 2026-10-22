package plugin

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	azureauth "github.com/praetorian-inc/aurelian/pkg/azure/auth"
	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

// AzureReconBase contains base parameters shared by all Azure recon modules.
type AzureReconBase struct {
	OutputDir string                 `param:"output-dir" desc:"Base output directory" default:"aurelian-output"`
	CloudType string                 `param:"cloud-type" desc:"Azure deployment: public (Commercial/GCC) or gcc-high (GCC High); anything else defaults to public" default:"public"`
	Env       azurecloud.Environment `param:"-"`
}

// AzureCommonRecon contains common parameters for Azure reconnaissance modules.
type AzureCommonRecon struct {
	AzureReconBase
	Concurrency     int                    `param:"concurrency" desc:"Maximum concurrent API requests" default:"5"`
	SubscriptionIDs []string               `param:"subscription-ids" desc:"Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions" default:"all" shortcode:"s"`
	AzureCredential azcore.TokenCredential `param:"-"`
}

func (c *AzureCommonRecon) PostBind(_ Config, module Module) error {
	c.Env = azurecloud.Resolve(c.CloudType)
	// Only these module paths have Government support; fail closed for new modules.
	if c.Env.Name == azurecloud.Government && module != nil {
		switch module.ID() {
		case "list-all", "configuration-scan", "public-resources", "find-secrets", "subdomain-takeover":
		default:
			return fmt.Errorf("azure government is not supported for module %q", module.ID())
		}
	}
	// A reused module must not retain the previous cloud's credential chain/cache.
	cred, err := azureauth.NewAzureCredential(c.Env)
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}
	c.AzureCredential = cred
	c.Concurrency = max(1, c.Concurrency)
	return nil
}

// AzureEntraRecon contains parameters for Entra ID (Azure AD) modules that
// operate at the tenant level and do not require subscription IDs.
type AzureEntraRecon struct {
	AzureReconBase
	AzureCredential azcore.TokenCredential `param:"-"`
}

func (c *AzureEntraRecon) PostBind(_ Config, _ Module) error {
	c.Env = azurecloud.Resolve(c.CloudType)
	// Entra modules still use the Public Graph endpoints and scopes.
	if c.Env.Name == azurecloud.Government {
		return fmt.Errorf("azure government is not supported for Aurelian Entra modules")
	}
	cred, err := azureauth.NewAzureCredential(c.Env)
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}
	c.AzureCredential = cred
	return nil
}
