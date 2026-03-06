//go:build integration

package testutil

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// RunAndCollect executes a module with the given config and collects all results.
func RunAndCollect(t *testing.T, mod plugin.Module, cfg plugin.Config) ([]model.AurelianModel, error) {
	t.Helper()
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)
	return p2.Collect()
}

// AssertResultContainsARN checks that at least one result references the given ARN.
func AssertResultContainsARN(t *testing.T, results []model.AurelianModel, arn string) {
	t.Helper()
	for _, r := range results {
		if containsString(r, arn) {
			return
		}
	}
	t.Errorf("expected ARN %s in results (%d results checked)", arn, len(results))
}

// AssertResultContainsString checks that at least one result contains the substring.
func AssertResultContainsString(t *testing.T, results []model.AurelianModel, substr string) {
	t.Helper()
	for _, r := range results {
		if containsString(r, substr) {
			return
		}
	}
	t.Errorf("expected %q in results (%d results checked)", substr, len(results))
}

// AssertMinResults checks that at least min results were returned.
func AssertMinResults(t *testing.T, results []model.AurelianModel, min int) {
	t.Helper()
	if len(results) < min {
		t.Errorf("expected at least %d results, got %d", min, len(results))
	}
}

// AssertNoDuplicateResults checks that no two results serialize to the same JSON.
func AssertNoDuplicateResults(t *testing.T, results []model.AurelianModel) {
	t.Helper()
	seen := make(map[string]int)
	for _, r := range results {
		raw, err := json.Marshal(r)
		if err != nil {
			continue
		}
		seen[string(raw)]++
	}
	for key, count := range seen {
		if count > 1 {
			t.Errorf("result appears %d times: %s", count, key[:min(len(key), 200)])
		}
	}
}

// ResultsContainString reports whether any result contains substr
// (case-insensitive). Useful in retry loops where a testing.T is not appropriate.
func ResultsContainString(results []model.AurelianModel, substr string) bool {
	for _, r := range results {
		if containsString(r, substr) {
			return true
		}
	}
	return false
}

// containsString searches a value for a case-insensitive substring match.
func containsString(data any, substr string) bool {
	// JSON round-trip normalizes concrete types (e.g., map[string][]AWSResource)
	// to interface types (map[string]any, []model.AurelianModel) for reliable recursive traversal.
	raw, err := json.Marshal(data)
	if err == nil {
		var normalized any
		if json.Unmarshal(raw, &normalized) == nil {
			return searchNormalized(normalized, strings.ToLower(substr))
		}
	}
	return strings.Contains(strings.ToLower(fmt.Sprintf("%v", data)), strings.ToLower(substr))
}

// searchNormalized recursively searches JSON-normalized data for a
// case-insensitive substring. The substr parameter must already be lowercased.
func searchNormalized(data any, lowerSubstr string) bool {
	switch v := data.(type) {
	case string:
		return strings.Contains(strings.ToLower(v), lowerSubstr)
	case map[string]any:
		for _, val := range v {
			if searchNormalized(val, lowerSubstr) {
				return true
			}
		}
	case []model.AurelianModel:
		for _, val := range v {
			if searchNormalized(val, lowerSubstr) {
				return true
			}
		}
	default:
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), lowerSubstr)
	}
	return false
}
