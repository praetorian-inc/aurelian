package cache

import (
	"testing"
)

// testMapImplementation runs the same suite against any Map[string] impl.
func testMapImplementation(t *testing.T, m Map[string]) {
	t.Helper()

	// Empty
	if m.Len() != 0 {
		t.Fatalf("expected len 0, got %d", m.Len())
	}
	if _, ok := m.Get("missing"); ok {
		t.Fatal("expected miss on empty map")
	}

	// Set and Get
	m.Set("a", "alpha")
	m.Set("b", "beta")
	if m.Len() != 2 {
		t.Fatalf("expected len 2, got %d", m.Len())
	}
	v, ok := m.Get("a")
	if !ok || v != "alpha" {
		t.Fatalf("Get(a) = %q, %v; want alpha, true", v, ok)
	}

	// Overwrite
	m.Set("a", "ALPHA")
	if m.Len() != 2 {
		t.Fatalf("overwrite changed len: got %d", m.Len())
	}
	v, ok = m.Get("a")
	if !ok || v != "ALPHA" {
		t.Fatalf("Get(a) after overwrite = %q, %v", v, ok)
	}

	// Range
	seen := make(map[string]string)
	m.Range(func(k string, v string) bool {
		seen[k] = v
		return true
	})
	if len(seen) != 2 {
		t.Fatalf("Range saw %d entries, want 2", len(seen))
	}

	// Range early stop
	count := 0
	m.Range(func(k string, v string) bool {
		count++
		return false
	})
	if count != 1 {
		t.Fatalf("Range early stop: saw %d, want 1", count)
	}
}

func TestMemoryMap(t *testing.T) {
	testMapImplementation(t, NewMemoryMap[string]())
}

func TestSQLiteMap(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := NewSQLiteMap[string](db)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	testMapImplementation(t, m)
}

// Test with pointer types (matching AnalyzerState usage).
type testStruct struct {
	Name string `json:"name"`
	Val  int    `json:"val"`
}

func testMapPointers(t *testing.T, m Map[*testStruct]) {
	t.Helper()

	m.Set("x", &testStruct{Name: "foo", Val: 42})
	v, ok := m.Get("x")
	if !ok || v == nil || v.Name != "foo" || v.Val != 42 {
		t.Fatalf("pointer round-trip failed: %+v, %v", v, ok)
	}

	// Nil value
	m.Set("nil", nil)
	v, ok = m.Get("nil")
	if !ok {
		t.Fatal("expected to find nil entry")
	}
	if v != nil {
		t.Fatalf("expected nil, got %+v", v)
	}
}

func TestMemoryMapPointers(t *testing.T) {
	testMapPointers(t, NewMemoryMap[*testStruct]())
}

func TestSQLiteMapPointers(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := NewSQLiteMap[*testStruct](db)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	testMapPointers(t, m)
}

// Verify writes are batched and flushed correctly.
func TestSQLiteMapBatchedWrites(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Small threshold to exercise flush within test.
	m, err := NewSQLiteMapWithThreshold[string](db, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Two writes — still buffered (below threshold of 3).
	m.Set("a", "1")
	m.Set("b", "2")

	// Direct DB query should show 0 rows (not flushed yet).
	var count int
	db.QueryRow("SELECT COUNT(*) FROM " + m.table).Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 rows in DB before flush, got %d", count)
	}

	// Get should still find buffered data.
	v, ok := m.Get("a")
	if !ok || v != "1" {
		t.Fatalf("Get from buffer failed: %q, %v", v, ok)
	}

	// Third write triggers flush (threshold=3).
	m.Set("c", "3")
	db.QueryRow("SELECT COUNT(*) FROM " + m.table).Scan(&count)
	if count != 3 {
		t.Fatalf("expected 3 rows after threshold flush, got %d", count)
	}

	// Overwrite buffered key before flush.
	m.Set("d", "old")
	m.Set("d", "new")
	m.flush()
	v, ok = m.Get("d")
	if !ok || v != "new" {
		t.Fatalf("overwrite in buffer: got %q, %v", v, ok)
	}
	if m.Len() != 4 {
		t.Fatalf("expected len 4, got %d", m.Len())
	}

	// Range flushes and returns all.
	all := make(map[string]string)
	m.Range(func(k, v string) bool { all[k] = v; return true })
	if len(all) != 4 {
		t.Fatalf("Range returned %d entries, want 4", len(all))
	}
}

// Multiple SQLiteMaps sharing one DB.
func TestSQLiteMapMultipleTables(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m1, err := NewSQLiteMap[string](db)
	if err != nil {
		t.Fatal(err)
	}
	defer m1.Close()

	m2, err := NewSQLiteMap[int](db)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()

	m1.Set("key", "value")
	m2.Set("key", 123)

	v1, _ := m1.Get("key")
	v2, _ := m2.Get("key")

	if v1 != "value" {
		t.Fatalf("m1 got %q", v1)
	}
	if v2 != 123 {
		t.Fatalf("m2 got %d", v2)
	}
}
