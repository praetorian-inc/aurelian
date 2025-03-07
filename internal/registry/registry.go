package registry

import (
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
)

type ModuleHeriarchy struct {
	Platform string
	Category string
}

type RegistryEntry struct {
	Module          chain.Module
	ModuleHeriarchy ModuleHeriarchy
}

type ModuleRegistry struct {
	mu        sync.RWMutex
	modules   map[string]RegistryEntry       // name -> module mapping
	hierarchy map[string]map[string][]string // platform -> category -> []name
}

var Registry = &ModuleRegistry{
	modules:   make(map[string]RegistryEntry),
	hierarchy: make(map[string]map[string][]string),
}

func Register(platform, category, name string, module chain.Module) {
	Registry.mu.Lock()
	defer Registry.mu.Unlock()

	// Store the module itself
	Registry.modules[name] = RegistryEntry{
		Module: module,
		ModuleHeriarchy: ModuleHeriarchy{
			Platform: platform,
			Category: category,
		},
	}

	// Update the hierarchy map
	if _, exists := Registry.hierarchy[platform]; !exists {
		Registry.hierarchy[platform] = make(map[string][]string)
	}

	if _, exists := Registry.hierarchy[platform][category]; !exists {
		Registry.hierarchy[platform][category] = []string{}
	}

	Registry.hierarchy[platform][category] = append(Registry.hierarchy[platform][category], name)
}

// GetModules retrieves all modules for a given platform
func GetModules(platform string) []chain.Module {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	var modules []chain.Module

	if categoryMap, exists := Registry.hierarchy[platform]; exists {
		for _, names := range categoryMap {
			for _, name := range names {
				modules = append(modules, Registry.modules[name].Module)
			}
		}
	}

	return modules
}

// GetModule gets a specific module by name
func GetModule(name string) (chain.Module, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	entry, exists := Registry.modules[name]
	if !exists {
		return chain.Module{}, false
	}

	return entry.Module, true
}

// Add a method to expose the hierarchy for CLI generation
func GetHierarchy() map[string]map[string][]string {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	// Return a copy to prevent modification of the original
	result := make(map[string]map[string][]string)
	for platform, categories := range Registry.hierarchy {
		result[platform] = make(map[string][]string)
		for category, modules := range categories {
			result[platform][category] = append([]string{}, modules...)
		}
	}

	return result
}

// GetRegistryEntry gets the full entry for a module
func GetRegistryEntry(name string) (RegistryEntry, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	entry, exists := Registry.modules[name]
	return entry, exists
}
