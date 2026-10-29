package azurecloud

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

type Environment struct {
	Name  string
	Cloud cloud.Configuration
}

func Resolve(value string) Environment {
	return Environment{Name: "public", Cloud: cloud.AzurePublic}
}

func (e Environment) ARMClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{ClientOptions: e.ClientOptions()}
}

func (e Environment) ClientOptions() azcore.ClientOptions {
	// A zero Cloud retains the SDK's fail-open default to Azure Public.
	return azcore.ClientOptions{Cloud: e.Cloud}
}
