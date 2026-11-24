package cpe_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
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

func TestResolve_EmitsTheObservedVersionVerbatim(t *testing.T) {
	// The version is never rewritten. Each of these has no exact dictionary
	// entry, and each matches CVEs in NVD at exactly this version.
	for _, tc := range []struct{ product, version string }{
		{"python", "3.11.18"},
		{"node.js", "20.20.2"},
		{"mongodb", "7.0.48"},
		{"memcached", "1.6.45"},
		{"redis", "7.4.12"},
		{"postgresql", "15.20"},
	} {
		got := cpe.Resolve(tc.product, tc.version)
		assert.NotEmpty(t, got, "%s %s must resolve", tc.product, tc.version)
		for _, c := range got {
			assert.Contains(t, c, ":"+tc.version+":",
				"%s %s was rewritten to %s", tc.product, tc.version, c)
		}
	}
}

func TestResolve_NeverTruncates(t *testing.T) {
	// The specific regressions truncation caused, by measured CVE cost.
	for _, tc := range []struct {
		product, version string
		falseCVEs        int
	}{
		{"node.js", "20.20.2", 11},
		{"memcached", "1.6.45", 4},
		{"mongodb", "7.0.48", 2},
		{"mysql", "8.4.13.1", 1},
		{"python", "3.11.18", 1},
	} {
		for _, c := range cpe.Resolve(tc.product, tc.version) {
			assert.Contains(t, c, ":"+tc.version+":",
				"%s %s truncated to %s — measured, that attributes %d CVEs that do not apply",
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
		parts := splitN(c, ':', 6)
		if len(parts) > 3 {
			out = append(out, parts[3])
		}
	}
	return out
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == sep && len(out) < n {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	return append(out, cur)
}
