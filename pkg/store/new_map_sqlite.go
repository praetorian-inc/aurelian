//go:build aurelian_sqlite_cache

package store

import (
	"database/sql"
	"fmt"
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

// NewMapMethods creates a new MapMethods backend. With the cache_sqlite build tag,
// this returns a disk-backed SQLite map. Falls back to in-memory if the database
// cannot be opened.
func NewMapMethods[T any]() MapMethods[T] {
	db := sharedDB()
	if db == nil {
		panic("store: failed to initialize sqlite db")
	}

	m, err := NewSQLiteMap[T](db)
	if err != nil {
		panic(fmt.Sprintf("store: failed to create sqlite map: %v", err))
	}

	return m
}

// CloseCache closes the shared SQLite database. Call once at shutdown.
func CloseCache() {
	if sqliteDB != nil {
		sqliteDB.Close()
	}
}
