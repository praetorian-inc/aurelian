package store

import "encoding/json"

// MemoryMap is an in-memory Map backed by a plain Go map.
type MemoryMap[T any] struct {
	data map[string]T
}

// NewMemoryMap creates an empty in-memory Map.
func NewMemoryMap[T any]() *MemoryMap[T] {
	return &MemoryMap[T]{data: make(map[string]T)}
}

func (m *MemoryMap[T]) Get(key string) (T, bool) {
	v, ok := m.data[key]
	return v, ok
}

func (m *MemoryMap[T]) Set(key string, value T) {
	m.data[key] = value
}

func (m *MemoryMap[T]) Range(fn func(string, T) bool) {
	for k, v := range m.data {
		if !fn(k, v) {
			return
		}
	}
}

func (m *MemoryMap[T]) Len() int {
	return len(m.data)
}

func (m *MemoryMap[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.data)
}

func (m *MemoryMap[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.data)
}
