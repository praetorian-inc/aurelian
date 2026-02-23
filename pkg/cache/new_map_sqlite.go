//go:build aurelian_sqlite_cache

package cache

import (
	"database/sql"
	"log/slog"
	"sync"
)

var (
	sqliteOnce sync.Once
	sqliteDB   *sql.DB
)

func sharedDB() *sql.DB {
	sqliteOnce.Do(func() {
		db, err := OpenSQLiteDB("")
		if err != nil {
			slog.Error("cache: failed to open sqlite db", "error", err)
			return
		}
		sqliteDB = db
	})
	return sqliteDB
}

// NewMap creates a new Map. With the cache_sqlite build tag, this returns a
// disk-backed SQLite map. Falls back to in-memory if the database cannot be opened.
func NewMap[T any]() Map[T] {
	db := sharedDB()
	if db == nil {
		slog.Warn("cache: sqlite unavailable, falling back to memory")
		return NewMemoryMap[T]()
	}
	m, err := NewSQLiteMap[T](db)
	if err != nil {
		slog.Error("cache: failed to create sqlite map, falling back to memory", "error", err)
		return NewMemoryMap[T]()
	}
	return m
}

// CloseCache closes the shared SQLite database. Call once at shutdown.
func CloseCache() {
	if sqliteDB != nil {
		sqliteDB.Close()
	}
}
