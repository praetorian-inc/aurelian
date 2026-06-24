package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

// Sink consumes module results one at a time as they stream off the pipeline.
// Implementations either write each item immediately (JSONLSink) or buffer for a
// batch operation (Neo4jSink). Exactly one of Close (success) or Abort (failure)
// is called once after the last Write.
type Sink interface {
	// Write is called once per streamed result item.
	Write(item model.AurelianModel) error
	// Close flushes and finalizes on the success path.
	Close() error
	// Abort finalizes on the failure path, discarding any partial output.
	Abort() error
}

// JSONLSink streams results to a file as JSON Lines (one JSON object per line).
// The file (and its parent directory) is created lazily on the first Write, so a
// run that produces zero items leaves no file and no directory behind.
type JSONLSink struct {
	path string
	f    *os.File
	w    *bufio.Writer
	enc  *json.Encoder
}

// NewJSONLSink returns a JSONLSink targeting path. No filesystem work is done
// until the first Write.
func NewJSONLSink(path string) *JSONLSink {
	return &JSONLSink{path: path}
}

func (s *JSONLSink) ensureOpen() error {
	if s.f != nil {
		return nil
	}
	if err := utils.EnsureFileDirectory(s.path); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	f, err := os.Create(s.path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	s.f = f
	s.w = bufio.NewWriter(f)
	s.enc = json.NewEncoder(s.w) // compact; emits a trailing newline per Encode
	return nil
}

// Write lazily opens the file on first call and encodes item as one JSON line.
func (s *JSONLSink) Write(item model.AurelianModel) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.enc.Encode(item)
}

// Close flushes and closes the file, keeping it. No-op if nothing was written.
func (s *JSONLSink) Close() error {
	if s.f == nil {
		return nil
	}
	flushErr := s.w.Flush()
	closeErr := s.f.Close()
	s.f, s.w, s.enc = nil, nil, nil
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// Abort closes and removes the partial file. No-op if nothing was written.
func (s *JSONLSink) Abort() error {
	if s.f == nil {
		return nil
	}
	_ = s.w.Flush()
	_ = s.f.Close()
	s.f, s.w, s.enc = nil, nil, nil
	return os.Remove(s.path)
}
