package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	_ "modernc.org/sqlite"
)

var tableCounter atomic.Int64

const defaultFlushThreshold = 1000

type pendingWrite struct {
	key string
	raw []byte
}

// SQLiteMap is a disk-backed Map using SQLite for storage.
// Values are JSON-serialized into a BLOB column. Writes are buffered
// and flushed in a single transaction when the buffer reaches a threshold
// or when a read operation requires consistent data.
type SQLiteMap[T any] struct {
	db    *sql.DB
	table string
	count int

	// Prepared statements for hot paths.
	stmtGet    *sql.Stmt
	stmtInsert *sql.Stmt

	// Transaction state.
	inTransaction bool

	// Write buffer. Flushed on reads or when len(pending) >= flushThreshold.
	pending        []pendingWrite
	pendingKeys    map[string]int // key → index into pending (last write wins)
	flushThreshold int
}

// NewSQLiteMap creates a new SQLite-backed Map. Each instance gets a unique
// table within a temporary database file. The caller should call Close when
// the map is no longer needed.
func NewSQLiteMap[T any](db *sql.DB) (*SQLiteMap[T], error) {
	return NewSQLiteMapWithThreshold[T](db, defaultFlushThreshold)
}

// NewSQLiteMapWithThreshold is like NewSQLiteMap but allows configuring the
// write-buffer flush threshold.
func NewSQLiteMapWithThreshold[T any](db *sql.DB, flushThreshold int) (*SQLiteMap[T], error) {
	table := fmt.Sprintf("cache_%d", tableCounter.Add(1))

	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		key   TEXT PRIMARY KEY,
		value BLOB NOT NULL
	)`, table)
	if _, err := db.Exec(ddl); err != nil {
		return nil, fmt.Errorf("cache: create table %s: %w", table, err)
	}

	stmtGet, err := db.Prepare(fmt.Sprintf("SELECT value FROM %s WHERE key = ?", table))
	if err != nil {
		return nil, fmt.Errorf("cache: prepare get: %w", err)
	}

	stmtInsert, err := db.Prepare(fmt.Sprintf(
		"INSERT INTO %s (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		table,
	))
	if err != nil {
		return nil, fmt.Errorf("cache: prepare insert: %w", err)
	}

	if flushThreshold <= 0 {
		flushThreshold = defaultFlushThreshold
	}

	return &SQLiteMap[T]{
		db:             db,
		table:          table,
		stmtGet:        stmtGet,
		stmtInsert:     stmtInsert,
		pending:        make([]pendingWrite, 0, flushThreshold),
		pendingKeys:    make(map[string]int),
		flushThreshold: flushThreshold,
	}, nil
}

func (m *SQLiteMap[T]) ensureTransaction() error {
	if m.inTransaction {
		return nil
	}
	if _, err := m.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("cache: begin immediate: %w", err)
	}
	m.inTransaction = true
	return nil
}

func (m *SQLiteMap[T]) commitTransaction() error {
	if !m.inTransaction {
		return nil
	}
	if _, err := m.db.Exec("COMMIT"); err != nil {
		return fmt.Errorf("cache: commit: %w", err)
	}
	m.inTransaction = false
	return nil
}

// flush writes all buffered entries to SQLite in a single transaction.
func (m *SQLiteMap[T]) flush() {
	if len(m.pending) == 0 {
		return
	}

	if err := m.ensureTransaction(); err != nil {
		slog.Error("cache: flush ensure tx", "table", m.table, "error", err)
		return
	}

	for _, w := range m.pending {
		if _, err := m.stmtInsert.Exec(w.key, w.raw); err != nil {
			slog.Error("cache: tx insert", "table", m.table, "key", w.key, "error", err)
		}
	}

	if err := m.commitTransaction(); err != nil {
		slog.Error("cache: flush commit", "table", m.table, "error", err)
	}

	m.pending = m.pending[:0]
	m.pendingKeys = make(map[string]int)
}

func (m *SQLiteMap[T]) Get(key string) (T, bool) {
	// Check the write buffer first (unflushed data).
	if idx, ok := m.pendingKeys[key]; ok {
		var v T
		if err := json.Unmarshal(m.pending[idx].raw, &v); err != nil {
			slog.Error("cache: unmarshal pending", "table", m.table, "key", key, "error", err)
			var zero T
			return zero, false
		}
		return v, true
	}

	var raw []byte
	err := m.stmtGet.QueryRow(key).Scan(&raw)
	if err != nil {
		var zero T
		return zero, false
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		slog.Error("cache: unmarshal", "table", m.table, "key", key, "error", err)
		var zero T
		return zero, false
	}
	return v, true
}

func (m *SQLiteMap[T]) Set(key string, value T) {
	raw, err := json.Marshal(value)
	if err != nil {
		slog.Error("cache: marshal", "table", m.table, "key", key, "error", err)
		return
	}

	if idx, ok := m.pendingKeys[key]; ok {
		// Overwrite existing buffered entry in place.
		m.pending[idx].raw = raw
	} else {
		// Track count for new keys. Check both buffer and DB.
		var dummy []byte
		if err := m.stmtGet.QueryRow(key).Scan(&dummy); err != nil {
			m.count++
		}
		m.pendingKeys[key] = len(m.pending)
		m.pending = append(m.pending, pendingWrite{key: key, raw: raw})
	}

	if len(m.pending) >= m.flushThreshold {
		m.flush()
	}
}

func (m *SQLiteMap[T]) Range(fn func(string, T) bool) {
	m.flush()

	rows, err := m.db.Query(fmt.Sprintf("SELECT key, value FROM %s", m.table))
	if err != nil {
		slog.Error("cache: range query", "table", m.table, "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			slog.Error("cache: range scan", "table", m.table, "error", err)
			continue
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			slog.Error("cache: range unmarshal", "table", m.table, "key", key, "error", err)
			continue
		}
		if !fn(key, v) {
			return
		}
	}
}

func (m *SQLiteMap[T]) Len() int {
	return m.count
}

func (m *SQLiteMap[T]) Close() error {
	m.flush()
	var firstErr error
	if m.stmtGet != nil {
		if err := m.stmtGet.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.stmtInsert != nil {
		if err := m.stmtInsert.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// OpenSQLiteDB opens (or creates) a SQLite database at path suitable for use
// with SQLiteMap instances. It applies pragmas for bulk-write performance.
// If path is empty, a temporary file is created.
func OpenSQLiteDB(path string) (*sql.DB, error) {
	if path == "" {
		f, err := os.CreateTemp("", "cache-*.db")
		if err != nil {
			return nil, fmt.Errorf("cache: create temp db: %w", err)
		}
		path = f.Name()
		f.Close()
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("cache: open sqlite %s: %w", path, err)
	}

	// Performance pragmas for write-heavy ephemeral data.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=OFF",
		"PRAGMA temp_store=MEMORY",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("cache: %s: %w", pragma, err)
		}
	}

	return db, nil
}
