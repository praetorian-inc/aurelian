// Package cache provides a generic key-value caching abstraction with
// swappable backends (in-memory or SQLite-backed). It is designed as a
// drop-in replacement for map[string]T in components that need to hold
// large amounts of data and may need to trade speed for memory usage.
//
// The backend is selected at build time via build tags:
//
//	go build                    # default: in-memory
//	go build -tags cache_sqlite # SQLite-backed (disk, lower memory)
package store

// MapMethods is the backend interface for key-value storage.
// Implementations must be safe for sequential use; concurrent access
// requires external synchronization.
type MapMethods[T any] interface {
	// Get returns the value for key and whether it was found.
	Get(key string) (T, bool)

	// Set stores a value under the given key, overwriting any existing entry.
	Set(key string, value T)

	// Range iterates over all entries. Return false from fn to stop early.
	Range(fn func(key string, value T) bool)

	// RangeWithKeyFilter iterates over all entries but only calls fn for entries
	// where filter(key) returns true. This allows backends to skip expensive
	// deserialization for non-matching keys.
	RangeWithKeyFilter(filter func(key string) bool, fn func(key string, value T) bool)

	// Len returns the number of entries.
	Len() int

	// MarshalJSON returns the JSON encoding of the map.
	MarshalJSON() ([]byte, error)

	// UnmarshalJSON replaces the map contents from JSON.
	UnmarshalJSON(data []byte) error
}

// Map is a concrete wrapper around a MapMethods backend.
// A zero-value Map (nil backend) is safe to use: reads return zero values
// and iterations are no-ops. This eliminates nil checks at call sites.
type Map[T any] struct {
	m MapMethods[T]
}

// NewMap creates a new Map with the build-tag-selected backend.
func NewMap[T any]() Map[T] {
	return Map[T]{m: NewMapMethods[T]()}
}

// WrapMap wraps an existing MapMethods implementation in a Map.
func WrapMap[T any](methods MapMethods[T]) Map[T] {
	return Map[T]{m: methods}
}

// Get returns the value for key and whether it was found.
// Returns the zero value and false if the backend is nil.
func (m Map[T]) Get(key string) (T, bool) {
	if m.m == nil {
		var zero T
		return zero, false
	}
	return m.m.Get(key)
}

// Set stores a value under the given key. Panics if the backend is nil.
func (m Map[T]) Set(key string, value T) {
	m.m.Set(key, value)
}

// Range iterates over all entries. Does nothing if the backend is nil.
func (m Map[T]) Range(fn func(key string, value T) bool) {
	if m.m == nil {
		return
	}
	m.m.Range(fn)
}

// RangeWithKeyFilter iterates over entries where filter(key) returns true.
// Does nothing if the backend is nil.
func (m Map[T]) RangeWithKeyFilter(filter func(key string) bool, fn func(key string, value T) bool) {
	if m.m == nil {
		return
	}
	m.m.RangeWithKeyFilter(filter, fn)
}

// Len returns the number of entries, or 0 if the backend is nil.
func (m Map[T]) Len() int {
	if m.m == nil {
		return 0
	}
	return m.m.Len()
}

// IsZero returns true if the Map has no backend (zero value).
func (m Map[T]) IsZero() bool {
	return m.m == nil
}

// MarshalJSON implements json.Marshaler.
func (m Map[T]) MarshalJSON() ([]byte, error) {
	if m.m == nil {
		return []byte("{}"), nil
	}
	return m.m.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (m *Map[T]) UnmarshalJSON(data []byte) error {
	if m.m == nil {
		m.m = NewMapMethods[T]()
	}
	return m.m.UnmarshalJSON(data)
}
