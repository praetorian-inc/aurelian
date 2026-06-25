package plugin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONLSink_WritesOneObjectPerLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	s := NewJSONLSink(path)

	items := []output.AurelianRisk{
		{Name: "finding-1"},
		{Name: "finding-2"},
		{Name: "finding-3"},
	}
	for _, it := range items {
		require.NoError(t, s.Write(it))
	}
	require.NoError(t, s.Close())

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var obj map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &obj), "each line must be valid JSON")
		lines++
	}
	require.NoError(t, sc.Err())
	assert.Equal(t, 3, lines, "one JSON object per line")
}

func TestJSONLSink_ZeroWritesCreatesNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "out.jsonl")
	s := NewJSONLSink(path)

	require.NoError(t, s.Close())

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "no file on zero writes")
	_, dirErr := os.Stat(filepath.Dir(path))
	assert.True(t, os.IsNotExist(dirErr), "no parent dir created on zero writes")
}

func TestJSONLSink_AbortRemovesPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	s := NewJSONLSink(path)

	require.NoError(t, s.Write(output.AurelianRisk{Name: "partial"}))
	require.NoError(t, s.Abort())

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "Abort removes the partial file")
}

// TestJSONLSink_AbortPreservesExistingFile: writes stage through a temp file and
// are only renamed onto the final path on Close, so an aborted run must NOT
// truncate or delete a pre-existing file at the destination.
func TestJSONLSink_AbortPreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.jsonl")
	const original = "{\"name\":\"previous-good-report\"}\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	s := NewJSONLSink(path)
	require.NoError(t, s.Write(output.AurelianRisk{Name: "new-partial"}))
	require.NoError(t, s.Abort())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, original, string(got), "pre-existing report must survive an aborted run intact")
}

// TestJSONLSink_CloseReplacesExistingFile: a successful Close atomically replaces
// a pre-existing file with the new output.
func TestJSONLSink_CloseReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("{\"name\":\"stale\"}\n"), 0o644))

	s := NewJSONLSink(path)
	require.NoError(t, s.Write(output.AurelianRisk{Name: "fresh"}))
	require.NoError(t, s.Close())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(got), "fresh")
	assert.NotContains(t, string(got), "stale", "successful Close replaces the old file")
}

func TestNeo4jSink_SeedsOnlyGraphEntities(t *testing.T) {
	mock := &mockGraphDB{}
	gf := &GraphFormatter{db: mock, config: graph.NewConfig("bolt://x", "u", "p")}
	s := newNeo4jSinkWithFormatter(gf)

	// Mixed stream: a finding (ignored) + one node + one relationship (a rel
	// carries its own start/end nodes, which GraphFormatter ensures internally).
	require.NoError(t, s.Write(output.AurelianRisk{Name: "ignored-finding"}))
	require.NoError(t, s.Write(output.AWSIAMResource{}))
	require.NoError(t, s.Write(output.AWSIAMRelationship{Action: "iam:PassRole"}))

	require.NoError(t, s.Close())

	assert.NotEmpty(t, mock.nodesCreated, "graph entities are seeded")
	assert.NotEmpty(t, mock.queries, "enrichment queries run")
}

func TestNeo4jSink_EmptyEntitiesIsNoOpNotError(t *testing.T) {
	mock := &mockGraphDB{}
	gf := &GraphFormatter{db: mock, config: graph.NewConfig("bolt://x", "u", "p")}
	s := newNeo4jSinkWithFormatter(gf)

	// analyze-graph case: only findings, no graph entities.
	require.NoError(t, s.Write(output.AurelianRisk{Name: "risk-1"}))
	require.NoError(t, s.Write(output.AurelianRisk{Name: "risk-2"}))

	err := s.Close()
	require.NoError(t, err, "empty graph-entity buffer must be a no-op, not an error")
	assert.Empty(t, mock.nodesCreated, "nothing seeded when no graph entities present")
}
