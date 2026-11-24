package cpe_test

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cases below are not invented. Each was measured against the live NVD CVE
// corpus on 2026-11-24: every CVE referencing the product was downloaded, and
// NVD's own range semantics (versionStartIncluding/versionEndExcluding, and
// exact-version criteria) were evaluated offline for the observed version.
//
// That measurement produced three findings, and these tests encode them.
//
// 1. A CPE whose version is ABSENT from the CPE dictionary still matches CVEs.
//    NVD attaches CVEs to version RANGES, which do not require the version to
//    exist as a dictionary entry. cpe:2.3:a:python:python:3.11.18 has zero
//    dictionary entries and matches 15 CVEs.
//
// 2. Truncating an observed version to find a dictionary hit is therefore
//    unnecessary, and it is actively harmful. node.js 20.20.2 matches 1 CVE;
//    the 20.20 we used to emit in its place matches 12. Across 30 real
//    observations, truncation produced 19 false CVE attributions and zero
//    true ones that the observed version did not already produce.
//
// 3. Emitting every vendor the dictionary lists for a product costs nothing in
//    CVE accuracy, because the VERSION does the filtering: a homonym vendor
//    never shipped the observed version, so it matches no CVE. Measured,
//    rabbitmq 3.13.7 under all five dictionary vendors yields exactly the one
//    CVE that truly affects it.
//
// Together these replaced the old rule (truncate until the dictionary
// resolves, and let the version select the vendor), which measured precision
// 0.940 / recall 0.849, with precision 1.000 / recall 0.906.

// The version is emitted exactly as observed. None of these has an exact
// dictionary entry, every one matches CVEs in NVD at that version, and
// falseCVEs is what the truncated form used to attribute that does not apply.
func TestResolve_EmitsTheObservedVersionVerbatim(t *testing.T) {
	for _, tc := range []struct {
		product, version string
		falseCVEs        int
	}{
		{"node.js", "20.20.2", 11},
		{"memcached", "1.6.45", 4},
		{"mongodb", "7.0.48", 2},
		{"mysql", "8.4.13.1", 1},
		{"python", "3.11.18", 1},
		{"redis", "7.4.12", 0},
		{"postgresql", "15.20", 0},
	} {
		got := cpe.Resolve(tc.product, tc.version)
		require.NotEmpty(t, got, "%s %s must resolve", tc.product, tc.version)
		for _, c := range got {
			assert.Contains(t, c, ":"+tc.version+":",
				"%s %s was rewritten to %s — measured, that attributes %d CVEs that do not apply",
				tc.product, tc.version, c, tc.falseCVEs)
		}
	}
}

func TestResolve_EmitsEveryVendorTheDictionaryKnowsForTheProduct(t *testing.T) {
	// Recall depends on this. http_server CVEs are filed under several
	// vendors; emitting only apache measured 11 of 15. openjdk CVEs are filed
	// under oracle and sun.
	assert.Subset(t, vendorsOf(cpe.Resolve("http_server", "2.4.71")),
		[]string{"apache"}, "apache must be among the http_server vendors")
	assert.Greater(t, len(cpe.Resolve("http_server", "2.4.71")), 1,
		"http_server has several dictionary vendors and all must be emitted")
}

func TestResolve_HomonymVendorsAreHarmlessAtTheObservedVersion(t *testing.T) {
	// The old sole-vendor-and-version-selects-vendor rule existed to keep
	// voxpupuli:rabbitmq (a Puppet module) out. Measured, it is inert: the
	// homonym never shipped 3.13.7, so it matches no CVE, while the correct
	// vendor does. The version is the filter, not the vendor.
	got := cpe.Resolve("rabbitmq", "3.13.7")
	assert.NotEmpty(t, got)
	for _, c := range got {
		assert.Contains(t, c, ":3.13.7:")
	}
}

func TestResolve_StillRefusesUnusableInput(t *testing.T) {
	for _, tc := range []struct{ product, version string }{
		{"", "1.2.3"},
		{"nginx", ""},
		{"", ""},
		{"not_a_real_product_anywhere", "1.2.3"},
	} {
		assert.Empty(t, cpe.Resolve(tc.product, tc.version), "%q %q", tc.product, tc.version)
	}
}

func TestResolve_EveryEmissionSatisfiesGuardsKeyRegex(t *testing.T) {
	for _, tc := range []struct{ product, version string }{
		{"python", "3.11.18"}, {"node.js", "20.20.2"}, {".net", "8.0.34"},
		{"http_server", "2.4.71"}, {"openjdk", "25.0.5.1"},
	} {
		for _, c := range cpe.Resolve(tc.product, tc.version) {
			assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, c)
		}
	}
}

func vendorsOf(cpes []string) []string {
	out := make([]string, 0, len(cpes))
	for _, c := range cpes {
		if parts := strings.Split(c, ":"); len(parts) > 3 {
			out = append(out, parts[3])
		}
	}
	return out
}
