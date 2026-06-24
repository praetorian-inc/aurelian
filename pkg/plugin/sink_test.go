package plugin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
