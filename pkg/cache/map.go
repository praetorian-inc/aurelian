// Package cache provides a generic key-value caching abstraction with
// swappable backends (in-memory or SQLite-backed). It is designed as a
// drop-in replacement for map[string]T in components that need to hold
// large amounts of data and may need to trade speed for memory usage.
//
// The backend is selected at build time via build tags:
//
//	go build                    # default: in-memory
//	go build -tags cache_sqlite # SQLite-backed (disk, lower memory)
package cache

// Map is a generic key-value store keyed by string.
// Implementations must be safe for sequential use; concurrent access
// requires external synchronization.
type Map[T any] interface {
	// Get returns the value for key and whether it was found.
	Get(key string) (T, bool)

	// Set stores a value under the given key, overwriting any existing entry.
	Set(key string, value T)

	// Range iterates over all entries. Return false from fn to stop early.
	Range(fn func(key string, value T) bool)

	// Len returns the number of entries.
	Len() int
}
