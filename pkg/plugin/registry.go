package plugin

import (
	"fmt"
	"sync"
)

// RegistryEntry holds a module and its platform/category metadata
type RegistryEntry struct {
	Module   Module
	Platform Platform
	Category Category
}

// registry is the internal registry structure
type registry struct {
	mu        sync.RWMutex
	modules   map[string]RegistryEntry           // platform/category/id -> module
	hierarchy map[Platform]map[Category][]string // platform -> category -> []id
}

// Registry is the global module registry
var Registry = &registry{
	modules:   make(map[string]RegistryEntry),
	hierarchy: make(map[Platform]map[Category][]string),
}

// Register adds a module to the registry
// This function is thread-safe and can be called from init() functions
func Register(m Module) {
	Registry.mu.Lock()
	defer Registry.mu.Unlock()

	key := fmt.Sprintf("%s/%s/%s", m.Platform(), m.Category(), m.ID())

	if _, exists := Registry.modules[key]; exists {
		panic(fmt.Sprintf("module already registered: %s", key))
	}

	Registry.modules[key] = RegistryEntry{
		Module:   m,
		Platform: m.Platform(),
		Category: m.Category(),
	}

	// Update hierarchy
	if Registry.hierarchy[m.Platform()] == nil {
		Registry.hierarchy[m.Platform()] = make(map[Category][]string)
	}
	Registry.hierarchy[m.Platform()][m.Category()] = append(
		Registry.hierarchy[m.Platform()][m.Category()],
		m.ID(),
	)
}

// Get retrieves a module by platform, category, and ID
func Get(platform Platform, category Category, id string) (Module, bool) {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	key := fmt.Sprintf("%s/%s/%s", platform, category, id)
	entry, exists := Registry.modules[key]
	if !exists {
		return nil, false
	}
	return entry.Module, true
}

// GetHierarchy returns the complete module hierarchy for CLI generation
// The returned map is a copy, safe for concurrent use
func GetHierarchy() map[Platform]map[Category][]string {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()

	result := make(map[Platform]map[Category][]string)
	for platform, categories := range Registry.hierarchy {
		result[platform] = make(map[Category][]string)
		for category, modules := range categories {
			result[platform][category] = append([]string{}, modules...)
		}
	}
	return result
}

// Count returns the total number of registered modules
func Count() int {
	Registry.mu.RLock()
	defer Registry.mu.RUnlock()
	return len(Registry.modules)
}
