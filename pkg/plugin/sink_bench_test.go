package plugin

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// makeBenchItems builds n synthetic findings sized like a real secret finding.
func makeBenchItems(n int) []model.AurelianModel {
	items := make([]model.AurelianModel, n)
	for i := range n {
		items[i] = output.AurelianRisk{Name: "secret-finding-" + strconv.Itoa(i)}
	}
	return items
}

var benchSizes = []int{1000, 100000}

// BenchmarkOutputCollect models the OLD output path (replaced by JSONLSink):
// accumulate the full slice, then pretty-print the whole thing to io.Discard.
// This is the exact work the removed Collect()+JSONFormatter{Pretty:true} did,
// inlined here so the comparison survives the type's deletion. B/op and allocs/op
// grow ~linearly with N (it holds every item plus the indented serialization).
func BenchmarkOutputCollect(b *testing.B) {
	for _, n := range benchSizes {
		items := makeBenchItems(n)
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var results []model.AurelianModel // grow like Collect()
				results = append(results, items...)
				enc := json.NewEncoder(io.Discard)
				enc.SetIndent("", "  ")
				if err := enc.Encode(results); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOutputStreaming models the NEW path: stream each item through the real
// JSONLSink public API to a temp file. B/op stays ~flat across N (one item in
// flight + fixed bufio buffer), and ns/op should be <= the Collect baseline at the
// same N. b.TempDir() writes are page-cached, so disk latency does not distort the
// memory comparison.
func BenchmarkOutputStreaming(b *testing.B) {
	for _, n := range benchSizes {
		items := makeBenchItems(n)
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			dir := b.TempDir()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				path := filepath.Join(dir, "bench-"+strconv.Itoa(i)+".jsonl")
				s := NewJSONLSink(path)
				for _, it := range items {
					if err := s.Write(it); err != nil {
						b.Fatal(err)
					}
				}
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
