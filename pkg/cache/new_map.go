//go:build !aurelian_sqlite_cache

package cache

// NewMap creates a new Map. With the default build, this returns an in-memory map.
// Build with -tags aurelian_sqlite_cache to use a disk-backed SQLite map instead.
func NewMap[T any]() Map[T] {
	return NewMemoryMap[T]()
}

// CloseCache is a no-op for the in-memory backend.
func CloseCache() {}
