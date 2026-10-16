package azurecloud

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

// ARMClientOptions applies the official SDK endpoint and audience.
func ARMClientOptions(cred azcore.TokenCredential) *arm.ClientOptions {
	options := ClientOptions()
	options.Cloud = ForCredential(cred).Cloud
	return &arm.ClientOptions{ClientOptions: options}
}

// ClientOptions uses the standard HTTP client, including its configured transport.
// This also lets offline callers inject a transport through http.DefaultTransport.
func ClientOptions() azcore.ClientOptions {
	return azcore.ClientOptions{Transport: http.DefaultClient}
}
