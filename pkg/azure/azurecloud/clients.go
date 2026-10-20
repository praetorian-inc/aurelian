package azurecloud

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

// ARMClientOptions applies the official SDK endpoint and audience.
func ARMClientOptions(env Environment) *arm.ClientOptions {
	if env.Name == "" {
		panic("azurecloud: unresolved Environment; azcore would silently default to Public")
	}
	options := ClientOptions()
	options.Cloud = env.Cloud
	return &arm.ClientOptions{ClientOptions: options}
}

// ClientOptions uses the standard HTTP client, including its configured transport.
// This also lets offline callers inject a transport through http.DefaultTransport.
func ClientOptions() azcore.ClientOptions {
	return azcore.ClientOptions{Transport: http.DefaultClient}
}
