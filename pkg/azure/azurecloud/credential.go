package azurecloud

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

type credential struct {
	azcore.TokenCredential
	environment Environment
}

// WithCloud associates explicit selection with even an externally supplied
// credential. Constructors downstream read the same metadata without globals.
func WithCloud(cred azcore.TokenCredential, cloudType string) (azcore.TokenCredential, error) {
	environment, err := Resolve(cloudType)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("Azure credential is nil")
	}
	if previous, ok := cred.(*credential); ok {
		if previous.environment.Name != environment.Name {
			return nil, fmt.Errorf("Azure credential cloud conflicts with module cloud selection")
		}
		return cred, nil
	}
	return &credential{TokenCredential: cred, environment: environment}, nil
}

// ForCredential preserves public behavior for existing callers and test credentials.
func ForCredential(cred azcore.TokenCredential) Environment {
	if configured, ok := cred.(*credential); ok {
		return configured.environment
	}
	environment, _ := Resolve(Public)
	return environment
}
