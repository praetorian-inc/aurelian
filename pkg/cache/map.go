// Package cache provides a generic key-value caching abstraction with
// swappable backends (in-memory or SQLite-backed). It is designed as a
// drop-in replacement for map[string]T in components that need to hold
// large amounts of data and may need to trade speed for memory usage.
package cache

// Map is a generic key-value store keyed by string.
// Implementations must be safe for sequential use; concurrent access
// requires external synchronization.
type Map[T any] interface {
	// Get returns the value for key and whether it was found.
	Get(key string) (T, bool)

	// Set stores a value under the given key, overwriting any existing entry.
	Set(key string, value T)

	// Len returns the number of entries.
	Len() int
}

// Backend selects the storage implementation.
type Backend int

const (
	// Memory stores entries in a Go map. Fast, but all data lives in heap.
	Memory Backend = iota

	// SQLite stores entries in a temporary SQLite database on disk.
	// Trades latency for lower memory usage.
	SQLite
)
