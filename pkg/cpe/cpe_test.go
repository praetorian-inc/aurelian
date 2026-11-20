package cpe_test

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_CriteriaShape(t *testing.T) {
	assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"},
		cpe.Resolve("nginx", "1.25.3"))
}

func TestResolve_EmitsNothingOnBadInput(t *testing.T) {
	assert.Empty(t, cpe.Resolve("nginx", ""))
	assert.Empty(t, cpe.Resolve("nginx", "1.2:3"))
	assert.Empty(t, cpe.Resolve("no_such_product_xyz", "1.0"))
	assert.Empty(t, cpe.Resolve("", "1.0"))
}

func TestResolve_VersionSelectsTheVendor(t *testing.T) {
	// "server" carries many live vendors and none ships 3.2.1 — a naming
	// coincidence, not an identification.
	assert.Empty(t, cpe.Resolve("server", "3.2.1"))
	// redis 7.0.5 exists only under vendor "redis", not "redislabs".
	assert.Equal(t, []string{"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"},
		cpe.Resolve("redis", "7.0.5"))
	// http_server 2.4.50 is apache's, not ibm's or oracle's.
	assert.Equal(t, []string{"cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"},
		cpe.Resolve("http_server", "2.4.50"))
}

func TestResolve_SatisfiesGuardKeyRegex(t *testing.T) {
	// Versions chosen because each is a real live dictionary entry, so every
	// case produces at least one CPE — otherwise the assertion body never runs
	// and the test passes vacuously.
	re := regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)
	for _, tc := range []struct{ product, version string }{
		{"nginx", "1.25.3"}, {"redis", "7.0.5"},
		{"http_server", "2.4.50"}, {"postgresql", "15.4"},
	} {
		got := cpe.Resolve(tc.product, tc.version)
		require.NotEmpty(t, got, "%s %s", tc.product, tc.version)
		for _, c := range got {
			assert.Regexp(t, re, c, "product %s", tc.product)
		}
	}
}

// Resolve takes a product as a caller spells it — a literal, unescaped string.
// NVD's formatted strings escape punctuation (it publishes `notepad\+\+`), and
// the generator must store the unescaped literal as the table key so a caller
// never has to know CPE's quoting rules. Storing the escaped spelling makes the
// literal miss the table entirely, and the escaped spelling get escaped a
// second time into a string NVD never publishes.
func TestResolve_ProductsWithPunctuationUseLiteralSpelling(t *testing.T) {
	// NVD publishes cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.9.6.4:*:...
	assert.Equal(t,
		[]string{`cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.9.6.4:*:*:*:*:*:*:*`},
		cpe.Resolve("notepad++", "8.9.6.4"))

	// The escaped spelling is not an input a caller should have to supply, and
	// must not resolve to a double-escaped string.
	for _, c := range cpe.Resolve(`notepad\+\+`, "8.9.6.4") {
		assert.NotContains(t, c, `\\`, "must never emit a double-escaped component")
	}
}

func TestResolveVendors_ProductKeysAreUnescaped(t *testing.T) {
	assert.NotEmpty(t, cpe.ResolveVendors("notepad++", "8.9.6.4"))
	// A product whose NVD spelling escapes a colon still keys on the literal.
	assert.NotEmpty(t, cpe.ResolveVendors("1c:enterprise", "8.3.13"))
}

// No emitted CPE may carry a double backslash, whatever the product spelling.
func TestResolve_NeverDoubleEscapes(t *testing.T) {
	for _, p := range []string{"notepad++", "c++_compiler_classic", "sendmail+pro", "deslock+"} {
		for _, c := range cpe.Resolve(p, "1.0") {
			assert.NotContains(t, c, `\\`, "product %s", p)
			assert.Regexp(t, keyRegexForTest, c, "product %s", p)
		}
	}
}

var keyRegexForTest = regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

// The open version-granularity gap, pinned as behaviour — and it cuts both
// ways. A minor-only version emits nothing only when the product has several
// vendors; where it has exactly one, rule 2 accepts the imprecise version.
func TestResolve_MinorOnlyVersionsEmitNothingForMultiVendorProducts(t *testing.T) {
	assert.Empty(t, cpe.Resolve("kubernetes", "1.29"))
	assert.Empty(t, cpe.Resolve("python", "3.12"))
	assert.Empty(t, cpe.Resolve("elasticsearch", "7.10"))
}

func TestResolve_MinorOnlyVersionsDoEmitForSoleVendorProducts(t *testing.T) {
	assert.Equal(t, []string{"cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*"}, cpe.Resolve("php", "8.1"))
	assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*"}, cpe.Resolve("nginx", "1.25"))
	assert.Equal(t, []string{"cpe:2.3:a:microsoft:.net:8:*:*:*:*:*:*:*"}, cpe.Resolve(".net", "8"))
}

func TestResolve_EmitsOneCPEPerVendorCarryingTheVersion(t *testing.T) {
	// Where more than one live vendor carries the same version, all are
	// emitted: a spurious node resolves to an empty CVE set, while a missing
	// one silently loses a real one.
	got := cpe.Resolve("http_server", "2.4.50")
	assert.Len(t, got, len(cpe.ResolveVendors("http_server", "2.4.50")))
}
