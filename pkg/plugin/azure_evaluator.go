package plugin

import (
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// AzureEvaluatorFunc checks enriched properties on an ARG query result.
// Returns true to confirm the finding, false to drop it.
type AzureEvaluatorFunc func(result templates.ARGQueryResult) bool

type azureEvaluatorRegistry struct {
	mu         sync.RWMutex
	evaluators map[string]AzureEvaluatorFunc
}

var globalAzureEvaluatorRegistry = &azureEvaluatorRegistry{
	evaluators: make(map[string]AzureEvaluatorFunc),
}

// RegisterAzureEvaluator registers an evaluator function for a template ID.
func RegisterAzureEvaluator(templateID string, fn AzureEvaluatorFunc) {
	globalAzureEvaluatorRegistry.mu.Lock()
	defer globalAzureEvaluatorRegistry.mu.Unlock()

	globalAzureEvaluatorRegistry.evaluators[templateID] = fn
}

// GetAzureEvaluator returns the evaluator for a template ID, if any.
func GetAzureEvaluator(templateID string) (AzureEvaluatorFunc, bool) {
	globalAzureEvaluatorRegistry.mu.RLock()
	defer globalAzureEvaluatorRegistry.mu.RUnlock()

	fn, ok := globalAzureEvaluatorRegistry.evaluators[templateID]
	return fn, ok
}

// ResetAzureEvaluatorRegistry clears all registered evaluators. Test utility only.
func ResetAzureEvaluatorRegistry() {
	globalAzureEvaluatorRegistry.mu.Lock()
	defer globalAzureEvaluatorRegistry.mu.Unlock()

	globalAzureEvaluatorRegistry.evaluators = make(map[string]AzureEvaluatorFunc)
}
