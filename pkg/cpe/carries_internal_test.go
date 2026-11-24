package cpe

import "testing"

// carriesVersion is the whole of rule 1's matching logic, and the committed
// dictionary is a poor place to test its edges: almost every real product has
// shipped almost every plausible version, so a table-driven assertion about
// "3.1 must not match 3.12.0" silently passes for the wrong reason — python
// really did ship 3.1.x. These cases use a synthetic version list so the
// boundary is the only thing under test.
func TestCarriesVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []string // must be sorted, as the generator writes them
		observed string
		want     bool
	}{
		{"exact match", []string{"1.8", "2.0"}, "1.8", true},
		{"exact match at the end", []string{"1.8", "2.0"}, "2.0", true},
		{"dotted prefix matches a patch line", []string{"3.12.0", "3.12.7"}, "3.12", true},
		{"dotted prefix matches a bare major", []string{"20.1.0", "20.11.1"}, "20", true},

		// The boundary. Without the trailing dot in the probe, "3.1" would
		// match "3.12.0" and claim a release line it has no evidence for.
		{"prefix stops at the component separator", []string{"3.12.0", "3.12.7"}, "3.1", false},
		{"a longer observed version is not a prefix", []string{"3.12"}, "3.12.7", false},
		{"digit extension is not a prefix", []string{"1.250"}, "1.25", false},
		{"unrelated version", []string{"1.8", "2.0"}, "9.9", false},
		{"empty observed version never matches", []string{"1.8"}, "", false},
		{"empty version list never matches", nil, "1.8", false},

		// The prefix probe lands past the end of the slice.
		{"probe sorts after every entry", []string{"1.0.0", "1.1.0"}, "2", false},
		// The prefix probe lands before every entry.
		{"probe sorts before every entry", []string{"9.0.0"}, "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := carriesVersion(tc.versions, tc.observed); got != tc.want {
				t.Errorf("carriesVersion(%q, %q) = %v, want %v",
					tc.versions, tc.observed, got, tc.want)
			}
		})
	}
}
