package store

import (
	"fmt"
	"testing"
)

// benchSQLiteMap creates a populated SQLiteMap[string] with n ARN-like entries.
func benchSQLiteMap(b *testing.B, n int) *SQLiteMap[string] {
	b.Helper()
	db, err := OpenSQLiteDB("")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	m, err := NewSQLiteMap[string](db)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = m.Close() })

	for i := 0; i < n; i++ {
		// ~10% of keys look like IAM ARNs, the rest are other services.
		var key string
		if i%10 == 0 {
			key = fmt.Sprintf("arn:aws:iam::%012d:role/role-%d", 100000000000+i, i)
		} else {
			key = fmt.Sprintf("arn:aws:s3:::bucket-%d/key-%d", i, i)
		}
		m.Set(key, fmt.Sprintf("value-%d", i))
	}
	// Flush all pending writes so benchmarks measure steady-state.
	m.mu.Lock()
	m.flush()
	m.mu.Unlock()

	return m
}

func BenchmarkSQLiteMap_Set(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			db, err := OpenSQLiteDB("")
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			m, err := NewSQLiteMap[string](db)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = m.Close() }()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("arn:aws:s3:::bucket-%d/key-%d", i%size, i)
				m.Set(key, "v")
			}
		})
	}
}

func BenchmarkSQLiteMap_Range(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			m := benchSQLiteMap(b, size)
			wrapped := WrapMap[string](m)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wrapped.Range(func(k, v string) bool {
					return true
				})
			}
		})
	}
}

func BenchmarkSQLiteMap_RangeWithKeyFilter(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			m := benchSQLiteMap(b, size)
			wrapped := WrapMap[string](m)

			// Filter matches ~10% of keys (IAM ARNs).
			filter := func(key string) bool {
				return len(key) > 12 && key[:12] == "arn:aws:iam:"
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wrapped.RangeWithKeyFilter(filter, func(k, v string) bool {
					return true
				})
			}
		})
	}
}
