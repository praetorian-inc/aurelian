package dispatcher

import (
	"fmt"
	"sync"
)

var (
	// Global registry mapping resource types to processor functions
	processorRegistry = make(map[string]ProcessFunc)
	registryMu        sync.RWMutex
)

// RegisterAWSSecretProcessor registers a processor function for a specific AWS resource type.
// This uses the init() pattern similar to database/sql driver registration.
//
// Example usage in processor files:
//
//	func init() {
//	    RegisterAWSSecretProcessor("AWS::EC2::Instance", ProcessEC2Instance)
//	}
func RegisterAWSSecretProcessor(resourceType string, processor ProcessFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if processor == nil {
		panic(fmt.Sprintf("dispatcher: RegisterAWSSecretProcessor processor is nil for type %s", resourceType))
	}
	if _, exists := processorRegistry[resourceType]; exists {
		panic(fmt.Sprintf("dispatcher: RegisterAWSSecretProcessor called twice for type %s", resourceType))
	}
	processorRegistry[resourceType] = processor
}

// GetAWSSecretProcessor retrieves the registered processor for a resource type.
// Returns nil if no processor is registered for the given type.
func GetAWSSecretProcessor(resourceType string) ProcessFunc {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return processorRegistry[resourceType]
}

// SupportedAWSSecretTypes returns all registered AWS resource types.
// Useful for validation and documentation.
func SupportedAWSSecretTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]string, 0, len(processorRegistry))
	for resourceType := range processorRegistry {
		types = append(types, resourceType)
	}
	return types
}
