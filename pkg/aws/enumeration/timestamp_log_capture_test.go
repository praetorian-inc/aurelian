package enumeration

import (
	"context"
	"log/slog"
	"sync"
	"testing"
)

// timestampFailureMsg is the message logTimestampFailure emits.
const timestampFailureMsg = "failed to read last-modified time; resource will always be scanned"

type loggedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// logRecorder captures slog records so a test can assert what was logged and at
// which level. It mirrors the recorder in pkg/aws/resourcetypes rather than
// adding a shared non-test import.
type logRecorder struct {
	mu      sync.Mutex
	records []loggedRecord
}

func (h *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *logRecorder) Handle(_ context.Context, r slog.Record) error {
	rec := loggedRecord{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, rec)
	return nil
}

func (h *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecorder) WithGroup(string) slog.Handler      { return h }

// timestampFailures returns the LastModified failure records logged at level.
func (h *logRecorder) timestampFailures(level slog.Level) []loggedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []loggedRecord
	for _, r := range h.records {
		if r.msg == timestampFailureMsg && r.level == level {
			out = append(out, r)
		}
	}
	return out
}

// captureLogs routes the default logger into a logRecorder for the test.
// Callers must not call t.Parallel(): this swaps the process-global logger.
func captureLogs(t *testing.T) *logRecorder {
	t.Helper()
	h := &logRecorder{}
	restore := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(restore) })
	return h
}
