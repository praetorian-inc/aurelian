package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
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
	mu sync.Mutex

	db    *sql.DB
	table string

	// Prepared statements for hot paths.
	stmtGet    *sql.Stmt
	stmtInsert *sql.Stmt
	stmtCount  *sql.Stmt
	insertSQL  string

	// Transaction state.
	tx *sql.Tx

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
		return nil, fmt.Errorf("store: create table %s: %w", table, err)
	}

	stmtGet, err := db.Prepare(fmt.Sprintf("SELECT value FROM %s WHERE key = ?", table))
	if err != nil {
		return nil, fmt.Errorf("store: prepare get: %w", err)
	}

	insertSQL := fmt.Sprintf(
		"INSERT INTO %s (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		table,
	)
	stmtInsert, err := db.Prepare(insertSQL)
	if err != nil {
		return nil, fmt.Errorf("store: prepare insert: %w", err)
	}

	stmtCount, err := db.Prepare(fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
	if err != nil {
		return nil, fmt.Errorf("store: prepare count: %w", err)
	}

	if flushThreshold <= 0 {
		flushThreshold = defaultFlushThreshold
	}

	return &SQLiteMap[T]{
		db:             db,
		table:          table,
		stmtGet:        stmtGet,
		stmtInsert:     stmtInsert,
		stmtCount:      stmtCount,
		insertSQL:      insertSQL,
		pending:        make([]pendingWrite, 0, flushThreshold),
		pendingKeys:    make(map[string]int),
		flushThreshold: flushThreshold,
	}, nil
}

func (m *SQLiteMap[T]) ensureTransaction() error {
	if m.tx != nil {
		return nil
	}
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	m.tx = tx
	return nil
}

func (m *SQLiteMap[T]) commitTransaction() error {
	if m.tx == nil {
		return nil
	}
	err := m.tx.Commit()
	m.tx = nil
	if err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// flush writes all buffered entries to SQLite in a single transaction.
// Caller must hold m.mu.
func (m *SQLiteMap[T]) flush() {
	if len(m.pending) == 0 {
		return
	}

	if err := m.ensureTransaction(); err != nil {
		slog.Error("store: flush ensure tx", "table", m.table, "error", err)
		return
	}

	txStmt, err := m.tx.Prepare(m.insertSQL)
	if err != nil {
		slog.Error("store: flush prepare", "table", m.table, "error", err)
		return
	}
	defer func() { _ = txStmt.Close() }()

	for _, w := range m.pending {
		if _, err := txStmt.Exec(w.key, w.raw); err != nil {
			slog.Error("store: tx insert", "table", m.table, "key", w.key, "error", err)
		}
	}

	if err := m.commitTransaction(); err != nil {
		slog.Error("store: flush commit", "table", m.table, "error", err)
	}

	m.pending = m.pending[:0]
	m.pendingKeys = make(map[string]int)
}

func (m *SQLiteMap[T]) Get(key string) (T, bool) {
	m.mu.Lock()

	// Check the write buffer first (unflushed data).
	if idx, ok := m.pendingKeys[key]; ok {
		// Copy the raw bytes so we can unmarshal outside the lock.
		raw := m.pending[idx].raw
		m.mu.Unlock()
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			slog.Error("store: unmarshal pending", "table", m.table, "key", key, "error", err)
			var zero T
			return zero, false
		}
		return v, true
	}

	// Flush pending writes so the DB query sees all data.
	m.flush()
	m.mu.Unlock()

	// stmtGet is safe for concurrent use after flush.
	var raw []byte
	err := m.stmtGet.QueryRow(key).Scan(&raw)
	if err != nil {
		var zero T
		return zero, false
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		slog.Error("store: unmarshal", "table", m.table, "key", key, "error", err)
		var zero T
		return zero, false
	}
	return v, true
}

func (m *SQLiteMap[T]) Set(key string, value T) {
	raw, err := json.Marshal(value)
	if err != nil {
		slog.Error("store: marshal", "table", m.table, "key", key, "error", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if idx, ok := m.pendingKeys[key]; ok {
		// Overwrite existing buffered entry in place.
		m.pending[idx].raw = raw
	} else {
		m.pendingKeys[key] = len(m.pending)
		m.pending = append(m.pending, pendingWrite{key: key, raw: raw})
	}

	if len(m.pending) >= m.flushThreshold {
		m.flush()
	}
}

func (m *SQLiteMap[T]) Range(fn func(string, T) bool) {
	m.mu.Lock()
	m.flush()
	m.mu.Unlock()

	// Row iteration runs outside the lock. The callback may call Get/Set on
	// *other* SQLiteMap instances (same shared DB), so holding the lock here
	// would risk deadlock. This map's own data is stable after flush — any
	// concurrent Set on this map will buffer until the next flush.
	rows, err := m.db.Query(fmt.Sprintf("SELECT key, value FROM %s", m.table))
	if err != nil {
		slog.Error("store: range query", "table", m.table, "error", err)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			slog.Error("store: range scan", "table", m.table, "error", err)
			continue
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			slog.Error("store: range unmarshal", "table", m.table, "key", key, "error", err)
			continue
		}
		if !fn(key, v) {
			return
		}
	}
}

func (m *SQLiteMap[T]) RangeWithKeyFilter(filter func(string) bool, fn func(string, T) bool) {
	m.mu.Lock()
	m.flush()
	m.mu.Unlock()

	rows, err := m.db.Query(fmt.Sprintf("SELECT key, value FROM %s", m.table))
	if err != nil {
		slog.Error("store: range query", "table", m.table, "error", err)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			slog.Error("store: range scan", "table", m.table, "error", err)
			continue
		}
		if !filter(key) {
			continue
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			slog.Error("store: range unmarshal", "table", m.table, "key", key, "error", err)
			continue
		}
		if !fn(key, v) {
			return
		}
	}
}

func (m *SQLiteMap[T]) Len() int {
	m.mu.Lock()
	m.flush()
	m.mu.Unlock()

	var count int
	if err := m.stmtCount.QueryRow().Scan(&count); err != nil {
		slog.Error("store: count", "table", m.table, "error", err)
		return 0
	}
	return count
}

func (m *SQLiteMap[T]) MarshalJSON() ([]byte, error) {
	panic("SQLiteMap does not support JSON marshaling")
}

func (m *SQLiteMap[T]) UnmarshalJSON([]byte) error {
	panic("SQLiteMap does not support JSON unmarshaling")
}

func (m *SQLiteMap[T]) Close() error {
	m.mu.Lock()
	m.flush()
	m.mu.Unlock()
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
	if m.stmtCount != nil {
		if err := m.stmtCount.Close(); err != nil && firstErr == nil {
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
			return nil, fmt.Errorf("store: create temp db: %w", err)
		}
		path = f.Name()
		_ = f.Close()
	}

	// Use DSN pragma syntax so every pooled connection gets the same settings.
	// db.Exec("PRAGMA ...") only applies to one connection; new pool connections
	// start with defaults, causing SQLITE_BUSY on connections without busy_timeout.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(OFF)&_pragma=temp_store(MEMORY)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite %s: %w", path, err)
	}

	return db, nil
}
