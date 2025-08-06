package registry

import (
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
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
	modules   map[string]RegistryEntry       // platform/category/name -> module mapping
	hierarchy map[string]map[string][]string // platform -> category -> []name
}

var Registry = &ModuleRegistry{
	modules:   make(map[string]RegistryEntry),
	hierarchy: make(map[string]map[string][]string),
}

func Register(platform, category, name string, module chain.Module) {
	Registry.mu.Lock()
	defer Registry.mu.Unlock()

	// Create composite key: platform/category/name
	key := platform + "/" + category + "/" + name
	
	// Store the module itself
	Registry.modules[key] = RegistryEntry{
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

// GetModule gets a specific module by name (legacy - searches all platforms)
func GetModule(name string) (chain.Module, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	// Search for the module across all platforms
	for key, entry := range Registry.modules {
		if getModuleNameFromKey(key) == name {
			return entry.Module, true
		}
	}

	return chain.Module{}, false
}

// GetModuleByPlatform gets a specific module by platform, category, and name
func GetModuleByPlatform(platform, category, name string) (chain.Module, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	key := platform + "/" + category + "/" + name
	entry, exists := Registry.modules[key]
	if !exists {
		return chain.Module{}, false
	}

	return entry.Module, true
}

// Add a method to expose the hierarchy for CLI generation
func GetHierarchy() map[string]map[string][]string {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	result := make(map[string]map[string][]string)
	for platform, categories := range Registry.hierarchy {
		result[platform] = make(map[string][]string)
		for category, modules := range categories {
			result[platform][category] = slices.Clone(modules)
		}
	}

	return result
}

// GetRegistryEntry gets the full entry for a module (legacy - searches all platforms)
func GetRegistryEntry(name string) (RegistryEntry, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	// Search for the module across all platforms
	for key, entry := range Registry.modules {
		if getModuleNameFromKey(key) == name {
			return entry, true
		}
	}

	return RegistryEntry{}, false
}

// GetRegistryEntryByPlatform gets the full entry for a module by platform, category, and name
func GetRegistryEntryByPlatform(platform, category, name string) (RegistryEntry, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	key := platform + "/" + category + "/" + name
	entry, exists := Registry.modules[key]
	return entry, exists
}

func GetModuleCount() int {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	return len(Registry.modules)
}

func FormatMcpToolName(name string) string {
	// Limit name to 64 characters and replace invalid characters
	name = regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(name, "")
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// getModuleNameFromKey extracts the module name from composite key "platform/category/name"
func getModuleNameFromKey(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) == 3 {
		return parts[2]
	}
	return key // fallback for malformed keys
}
