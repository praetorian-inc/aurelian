package store

import (
	"fmt"
	"sync"
	"testing"
)

// TestGetFromMapBWhileRangingMapA reproduces the deadlock that occurred with
// SetMaxOpenConns(1): Range on map A holds a DB connection for row iteration,
// and the callback calls Get on map B which needs another connection.
func TestGetFromMapBWhileRangingMapA(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mapA, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mapA.Close() }()

	mapB, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mapB.Close() }()

	// Populate both maps.
	for i := 0; i < 20; i++ {
		mapA.Set(fmt.Sprintf("a-%d", i), fmt.Sprintf("va-%d", i))
		mapB.Set(fmt.Sprintf("b-%d", i), fmt.Sprintf("vb-%d", i))
	}

	// Range over A, Get from B inside the callback.
	// This deadlocked when the DB was pinned to one connection.
	rangeCount := 0
	a := WrapMap[string](mapA)
	b := WrapMap[string](mapB)
	a.Range(func(k, v string) bool {
		rangeCount++
		// Read from the other map while iterating.
		val, ok := b.Get("b-0")
		if !ok || val != "vb-0" {
			t.Errorf("Get from mapB during Range(mapA): got %q, %v", val, ok)
		}
		return true
	})
	if rangeCount != 20 {
		t.Fatalf("expected 20 iterations, got %d", rangeCount)
	}
}

// TestSetToMapBWhileRangingMapA verifies that writing to map B from within
// a Range callback on map A works without deadlock or errors.
func TestSetToMapBWhileRangingMapA(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mapA, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mapA.Close() }()

	mapB, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mapB.Close() }()

	// Populate map A.
	for i := 0; i < 20; i++ {
		mapA.Set(fmt.Sprintf("a-%d", i), fmt.Sprintf("va-%d", i))
	}

	// Range over A, Set into B inside the callback.
	a := WrapMap[string](mapA)
	b := WrapMap[string](mapB)
	a.Range(func(k, v string) bool {
		b.Set("copied-"+k, v)
		return true
	})

	// Verify all items were copied.
	if b.Len() != 20 {
		t.Fatalf("expected 20 entries in mapB, got %d", b.Len())
	}
	val, ok := b.Get("copied-a-0")
	if !ok || val != "va-0" {
		t.Fatalf("copied value mismatch: %q, %v", val, ok)
	}
}

// TestConcurrentGetsOnSharedMap reproduces the "statement is closed" and
// "transaction already committed" errors that occurred when multiple goroutines
// called Get on the same SQLiteMap concurrently, racing into flush().
func TestConcurrentGetsOnSharedMap(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Use a large threshold so all writes stay buffered.
	m, err := NewSQLiteMapWithThreshold[string](db, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Buffer up writes without flushing.
	for i := 0; i < 200; i++ {
		m.Set(fmt.Sprintf("key-%d", i), fmt.Sprintf("val-%d", i))
	}

	// Hammer Get from many goroutines. The first Get triggers flush();
	// without the mutex this caused "transaction already committed" errors.
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", id%200)
			val, ok := m.Get(key)
			if !ok {
				errs <- fmt.Errorf("goroutine %d: Get(%q) not found", id, key)
				return
			}
			expected := fmt.Sprintf("val-%d", id%200)
			if val != expected {
				errs <- fmt.Errorf("goroutine %d: Get(%q) = %q, want %q", id, key, val, expected)
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestConcurrentSetsOnSharedMap verifies that concurrent Set calls on the
// same map don't race or corrupt data.
func TestConcurrentSetsOnSharedMap(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("g%d-k%d", id, i)
				m.Set(key, fmt.Sprintf("v%d-%d", id, i))
			}
		}(g)
	}
	wg.Wait()

	// Every key should be retrievable.
	for g := 0; g < 50; g++ {
		for i := 0; i < 20; i++ {
			key := fmt.Sprintf("g%d-k%d", g, i)
			if _, ok := m.Get(key); !ok {
				t.Errorf("missing key %q after concurrent Set", key)
			}
		}
	}
}

// TestConcurrentRangesOnSharedMap ensures multiple goroutines can Range
// over the same map simultaneously after it has been populated.
func TestConcurrentRangesOnSharedMap(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := NewSQLiteMapWithThreshold[string](db, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	for i := 0; i < 50; i++ {
		m.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("v%d", i))
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			count := 0
			WrapMap[string](m).Range(func(k, v string) bool {
				count++
				return true
			})
			if count != 50 {
				errs <- fmt.Errorf("goroutine %d: Range saw %d entries, want 50", id, count)
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestCreateTableWhileFlushInProgress reproduces the SQLITE_BUSY panic where
// NewSQLiteMap's CREATE TABLE was blocked by an in-flight flush transaction
// on a connection without busy_timeout (pre-DSN pragma fix).
func TestCreateTableWhileFlushInProgress(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create first map and buffer enough data to trigger a slow flush.
	m1, err := NewSQLiteMapWithThreshold[string](db, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m1.Close() }()

	for i := 0; i < 500; i++ {
		m1.Set(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i))
	}

	// Concurrently: flush m1 while creating new maps (DDL).
	// Without busy_timeout on all connections, CREATE TABLE could get SQLITE_BUSY.
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	// Trigger flush via Range in a goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		WrapMap[string](m1).Range(func(k, v string) bool { return true })
	}()

	// Simultaneously create several new maps (DDL operations).
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := NewSQLiteMap[string](db)
			if err != nil {
				errs <- fmt.Errorf("NewSQLiteMap during flush: %v", err)
				return
			}
			m.Close()
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestConcurrentGetAndSetDifferentMaps simulates the Analyze() pattern:
// eval workers call Get on the resource store while a collector goroutine
// calls Set on the results store, both sharing the same DB.
func TestConcurrentGetAndSetDifferentMaps(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// "resource store" — populated, then read concurrently.
	resources, err := NewSQLiteMapWithThreshold[string](db, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resources.Close() }()

	for i := 0; i < 200; i++ {
		resources.Set(fmt.Sprintf("res-%d", i), fmt.Sprintf("data-%d", i))
	}
	// Force flush so all data is in DB.
	WrapMap[string](resources).Range(func(k, v string) bool { return true })

	// "results store" — written concurrently via a collector.
	results, err := NewSQLiteMapWithThreshold[string](db, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = results.Close() }()

	// Simulate eval workers reading resources + collector writing results.
	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// Reader goroutines (eval workers).
	for g := 0; g < 30; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				key := fmt.Sprintf("res-%d", (id*50+i)%200)
				if _, ok := resources.Get(key); !ok {
					errs <- fmt.Errorf("reader %d: missing %q", id, key)
					return
				}
			}
		}(g)
	}

	// Writer goroutine (collector).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			results.Set(fmt.Sprintf("rel-%d", i), fmt.Sprintf("edge-%d", i))
		}
	}()

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify results are all present.
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("rel-%d", i)
		if _, ok := results.Get(key); !ok {
			t.Errorf("missing result %q", key)
		}
	}
}

// TestFlushDoesNotCorruptOnConcurrentAccess runs Get, Set, and Range
// from many goroutines simultaneously on the same map to shake out
// any remaining races. Run with -race to detect data races.
func TestFlushDoesNotCorruptOnConcurrentAccess(t *testing.T) {
	db, err := OpenSQLiteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := NewSQLiteMapWithThreshold[string](db, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	wrapped := WrapMap[string](m)

	var wg sync.WaitGroup

	// Writers.
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				wrapped.Set(fmt.Sprintf("w%d-%d", id, i), "v")
			}
		}(g)
	}

	// Readers.
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				wrapped.Get(fmt.Sprintf("w%d-%d", id, i))
			}
		}(g)
	}

	// Rangers.
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				wrapped.Range(func(k, v string) bool { return true })
			}
		}()
	}

	wg.Wait()
}
