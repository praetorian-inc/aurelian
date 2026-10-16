package extraction

import (
	"fmt"
	"net/url"
	"strings"

	armcosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

// cosmosRegionalEndpoints obtains an exact account-specific allowlist from ARM.
// The Cosmos SDK discovers regional destinations itself; that discovery must not
// grant permission to forward a bearer token to arbitrary service-returned URLs.
func cosmosRegionalEndpoints(ctx extractContext, subscriptionID, resourceGroup, accountName string) ([]string, error) {
	client, err := armcosmos.NewDatabaseAccountsClient(subscriptionID, ctx.Cred, azurecloud.ARMClientOptions(ctx.Cred))
	if err != nil {
		return nil, err
	}
	account, err := client.Get(ctx.Context, resourceGroup, accountName, nil)
	if err != nil {
		return nil, fmt.Errorf("read Cosmos account endpoint metadata: %w", err)
	}
	if account.Properties == nil {
		return nil, fmt.Errorf("Cosmos account endpoint metadata is missing")
	}
	suffix := azurecloud.ForCredential(ctx.Cred).CosmosSuffix
	var endpoints []string
	locations := append(append([]*armcosmos.Location(nil), account.Properties.ReadLocations...), account.Properties.WriteLocations...)
	for _, location := range locations {
		if location == nil || location.DocumentEndpoint == nil {
			continue
		}
		endpoint, err := validateCosmosRegionalEndpoint(*location.DocumentEndpoint, accountName, suffix)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func validateCosmosRegionalEndpoint(raw, accountName, suffix string) (string, error) {
	accountName = strings.ToLower(accountName)
	endpoint, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid Cosmos regional endpoint")
	}
	host := strings.ToLower(endpoint.Hostname())
	name, ok := strings.CutSuffix(host, "."+suffix)
	if !ok || !(name == accountName || strings.HasPrefix(name, accountName+"-") && name != accountName+"-") {
		return "", fmt.Errorf("Cosmos regional endpoint does not belong to the selected account/cloud")
	}
	expected, err := azurecloud.Endpoint(name, suffix)
	if err != nil {
		return "", err
	}
	if err := azurecloud.ValidateURL(raw, expected); err != nil {
		return "", err
	}
	if endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawQuery != "" {
		return "", fmt.Errorf("Cosmos regional endpoint contains a path or query")
	}
	return expected, nil
}
