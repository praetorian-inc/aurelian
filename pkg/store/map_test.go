package store

import (
	"testing"
)

// testMapImplementation runs the same suite against any Map[string].
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
	testMapImplementation(t, WrapMap[string](NewMemoryMap[string]()))
}

func TestSQLiteMap(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	m, err := NewSQLiteMap[string](db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	testMapImplementation(t, WrapMap[string](m))
}

func TestNewMap(t *testing.T) {
	m := NewMap[string]()
	m.Set("x", "y")
	v, ok := m.Get("x")
	if !ok || v != "y" {
		t.Fatalf("NewMap round-trip failed: %q, %v", v, ok)
	}
}

func TestZeroMap(t *testing.T) {
	var m Map[string]
	if !m.IsZero() {
		t.Fatal("expected zero map")
	}
	if m.Len() != 0 {
		t.Fatalf("expected len 0, got %d", m.Len())
	}
	if _, ok := m.Get("x"); ok {
		t.Fatal("expected miss on zero map")
	}
	// Range should be a no-op
	m.Range(func(k, v string) bool {
		t.Fatal("should not iterate on zero map")
		return true
	})
}

// testRangeWithKeyFilter verifies RangeWithKeyFilter on any Map[string].
func testRangeWithKeyFilter(t *testing.T, m Map[string]) {
	t.Helper()

	m.Set("arn:aws:iam::123456789012:role/admin", "iam-role")
	m.Set("arn:aws:s3:::my-bucket", "s3-bucket")
	m.Set("arn:aws:iam::123456789012:user/dev", "iam-user")
	m.Set("arn:aws:lambda:us-east-1:123456789012:function:foo", "lambda-fn")

	// Filter to IAM resources only.
	filter := func(key string) bool {
		return len(key) > 12 && key[:12] == "arn:aws:iam:"
	}

	seen := make(map[string]string)
	m.RangeWithKeyFilter(filter, func(k, v string) bool {
		seen[k] = v
		return true
	})

	if len(seen) != 2 {
		t.Fatalf("expected 2 IAM entries, got %d: %v", len(seen), seen)
	}
	if seen["arn:aws:iam::123456789012:role/admin"] != "iam-role" {
		t.Fatal("missing role entry")
	}
	if seen["arn:aws:iam::123456789012:user/dev"] != "iam-user" {
		t.Fatal("missing user entry")
	}

	// Early stop.
	count := 0
	m.RangeWithKeyFilter(filter, func(k, v string) bool {
		count++
		return false
	})
	if count != 1 {
		t.Fatalf("early stop: saw %d, want 1", count)
	}

	// Filter that matches nothing.
	count = 0
	m.RangeWithKeyFilter(func(string) bool { return false }, func(k, v string) bool {
		count++
		return true
	})
	if count != 0 {
		t.Fatalf("no-match filter: saw %d, want 0", count)
	}
}

func TestMemoryMapRangeWithKeyFilter(t *testing.T) {
	testRangeWithKeyFilter(t, WrapMap[string](NewMemoryMap[string]()))
}

func TestSQLiteMapRangeWithKeyFilter(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	m, err := NewSQLiteMap[string](db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	testRangeWithKeyFilter(t, WrapMap[string](m))
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
	testMapPointers(t, WrapMap[*testStruct](NewMemoryMap[*testStruct]()))
}

func TestSQLiteMapPointers(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	m, err := NewSQLiteMap[*testStruct](db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	testMapPointers(t, WrapMap[*testStruct](m))
}

// Verify writes are batched and flushed correctly.
func TestSQLiteMapBatchedWrites(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Small threshold to exercise flush within test.
	sm, err := NewSQLiteMapWithThreshold[string](db, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sm.Close() }()

	m := WrapMap[string](sm)

	// Two writes — still buffered (below threshold of 3).
	m.Set("a", "1")
	m.Set("b", "2")

	// Direct DB query should show 0 rows (not flushed yet).
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM " + sm.table).Scan(&count)
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
	_ = db.QueryRow("SELECT COUNT(*) FROM " + sm.table).Scan(&count)
	if count != 3 {
		t.Fatalf("expected 3 rows after threshold flush, got %d", count)
	}

	// Overwrite buffered key before flush.
	m.Set("d", "old")
	m.Set("d", "new")
	sm.flush()
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

	sm1, err := NewSQLiteMap[string](db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sm1.Close() }()

	sm2, err := NewSQLiteMap[int](db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sm2.Close() }()

	m1 := WrapMap[string](sm1)
	m2 := WrapMap[int](sm2)

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
