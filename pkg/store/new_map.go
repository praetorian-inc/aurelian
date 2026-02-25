//go:build !compute

package store

// NewMapMethods creates a new MapMethods backend.
// With the default build, this returns an in-memory map.
// Build with -tags aurelian_sqlite_cache to use a disk-backed SQLite map instead.
func NewMapMethods[T any]() MapMethods[T] {
	return NewMemoryMap[T]()
}

// CloseCache is a no-op for the in-memory backend.
func CloseCache() {}
