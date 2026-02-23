//go:build integration

package testutil

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

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

// containsString recursively searches a value for a substring match.
func containsString(data any, substr string) bool {
	// JSON round-trip normalizes concrete types (e.g., map[string][]AWSResource)
	// to interface types (map[string]any, []model.AurelianModel) for reliable recursive traversal.
	raw, err := json.Marshal(data)
	if err == nil {
		var normalized any
		if json.Unmarshal(raw, &normalized) == nil {
			return searchNormalized(normalized, substr)
		}
	}
	return strings.Contains(fmt.Sprintf("%v", data), substr)
}

// searchNormalized recursively searches JSON-normalized data for a substring.
func searchNormalized(data any, substr string) bool {
	switch v := data.(type) {
	case string:
		return strings.Contains(v, substr)
	case map[string]any:
		for _, val := range v {
			if searchNormalized(val, substr) {
				return true
			}
		}
	case []model.AurelianModel:
		for _, val := range v {
			if searchNormalized(val, substr) {
				return true
			}
		}
	default:
		return strings.Contains(fmt.Sprintf("%v", v), substr)
	}
	return false
}
