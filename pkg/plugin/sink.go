package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
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

// Neo4jSink buffers graph entities (AWSIAMResource / AWSIAMRelationship) as they
// stream and seeds them into Neo4j in a single batch at Close. Seeding is inherently
// batch (nodes -> relationships -> whole-graph enrichment), so it cannot stream; the
// buffered entity set is bounded by AWS IAM account quotas. Non-graph results (e.g.
// AurelianRisk from analyze-graph) are ignored, and an empty buffer is a logged
// no-op rather than an error.
type Neo4jSink struct {
	gf     *GraphFormatter
	buffer []model.AurelianModel
}

// NewNeo4jSink connects to Neo4j (verifying connectivity, so an unreachable URI
// fails before the scan begins) and returns a sink that seeds on Close.
func NewNeo4jSink(uri, username, password string) (*Neo4jSink, error) {
	gf, err := NewGraphFormatter(uri, username, password)
	if err != nil {
		return nil, err
	}
	return newNeo4jSinkWithFormatter(gf), nil
}

// newNeo4jSinkWithFormatter wraps an already-constructed GraphFormatter. Used by
// tests to inject a fake graph.GraphDatabase without a live connection.
func newNeo4jSinkWithFormatter(gf *GraphFormatter) *Neo4jSink {
	return &Neo4jSink{gf: gf}
}

func isGraphEntity(item model.AurelianModel) bool {
	switch item.(type) {
	case output.AWSIAMResource, output.AWSIAMRelationship:
		return true
	default:
		return false
	}
}

// Write buffers item only if it is a graph entity; all other types are ignored.
func (s *Neo4jSink) Write(item model.AurelianModel) error {
	if isGraphEntity(item) {
		s.buffer = append(s.buffer, item)
	}
	return nil
}

// Close seeds the buffered graph entities into Neo4j, then closes the connection.
// An empty buffer (no graph entities streamed) is a logged no-op, not an error.
func (s *Neo4jSink) Close() error {
	defer func() { _ = s.gf.Close() }()
	if len(s.buffer) == 0 {
		slog.Info("no graph entities in results, skipping Neo4j seeding")
		return nil
	}
	return s.gf.Format(s.buffer)
}

// Abort closes the Neo4j connection without seeding.
func (s *Neo4jSink) Abort() error {
	return s.gf.Close()
}
