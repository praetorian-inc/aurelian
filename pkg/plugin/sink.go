package plugin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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
//
// Writes are staged in a sibling temp file and atomically renamed onto the final
// path only on a successful Close, so: (1) a pre-existing file at the final path
// is never truncated until the new output is complete, (2) Abort (failure) leaves
// the final path untouched and removes only the temp file, and (3) readers never
// observe a partial file. The temp file (and the parent directory) is created
// lazily on the first Write, so a run that produces zero items leaves nothing
// behind.
type JSONLSink struct {
	path string
	tmp  string
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
	// Stage in a sibling temp file so the final path is only written atomically
	// on success (see Close); a mid-stream failure cannot truncate or delete an
	// existing file at s.path.
	f, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	s.tmp = f.Name()
	s.f = f
	s.w = bufio.NewWriter(f)
	s.enc = json.NewEncoder(s.w) // compact; emits a trailing newline per Encode
	return nil
}

// Write lazily opens the temp file on first call and encodes item as one JSON line.
func (s *JSONLSink) Write(item model.AurelianModel) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.enc.Encode(item)
}

// Close flushes the temp file and atomically renames it onto the final path.
// No-op if nothing was written. On flush/close failure the temp file is removed
// and the final path is left untouched.
func (s *JSONLSink) Close() error {
	if s.f == nil {
		return nil
	}
	tmp := s.tmp
	flushErr := s.w.Flush()
	closeErr := s.f.Close()
	s.f, s.w, s.enc, s.tmp = nil, nil, nil, ""
	if err := errors.Join(flushErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalizing output file: %w", err)
	}
	return nil
}

// Abort closes and removes the temp file, leaving the final path untouched.
// No-op if nothing was written.
func (s *JSONLSink) Abort() error {
	if s.f == nil {
		return nil
	}
	tmp := s.tmp
	_ = s.w.Flush()
	_ = s.f.Close()
	s.f, s.w, s.enc, s.tmp = nil, nil, nil, ""
	return os.Remove(tmp)
}

// Neo4jSink buffers graph entities (AWSIAMResource / AWSIAMRelationship) as they
// stream and seeds them into Neo4j in a single batch at Close. Seeding is inherently
// batch (nodes -> relationships -> whole-graph enrichment), so it cannot stream; the
// buffered entity set is bounded by AWS IAM account quotas.
//
// Content gate (the routing contract this sink owns): only graph entities are
// buffered; non-graph results (e.g. AurelianRisk) are ignored. So `recon graph`,
// which emits AWSIAMResource/AWSIAMRelationship, seeds the graph, while
// `analyze graph`, which reads the graph and emits only AurelianRisk findings,
// streams to JSONL with an empty buffer here -> Close is a logged no-op, NOT an
// error. Neo4j is always an *additive* sink: the JSONL file is written regardless,
// and seeding never replaces it.
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
	if len(s.buffer) == 0 {
		slog.Info("no graph entities in results, skipping Neo4j seeding")
		return s.gf.Close()
	}
	// Surface both a seeding failure and a DB-close failure rather than letting
	// the deferred close swallow its error.
	return errors.Join(s.gf.Format(s.buffer), s.gf.Close())
}

// Abort closes the Neo4j connection without seeding.
func (s *Neo4jSink) Abort() error {
	return s.gf.Close()
}
