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

// The version-granularity gap, closed. A minor-only version is the normal case
// for this design's inputs — a Lambda runtime is `python3.12`, never
// `python3.12.7` — and it now selects the vendor through the dotted-prefix arm
// of rule 1 rather than falling through to rule 3.
//
// The vendor is the part that must be right, and each of these is: NVD carries
// python:python:3.12.x, nodejs:node.js:20.x and elastic:elasticsearch:7.10.x.
// Only the emitted version is coarser than a dictionary row.
func TestResolve_MinorOnlyVersionsResolveThroughTheVendorThatShipsThem(t *testing.T) {
	assert.Equal(t, []string{"cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"},
		cpe.Resolve("python", "3.12"))
	assert.Equal(t, []string{"cpe:2.3:a:nodejs:node.js:20:*:*:*:*:*:*:*"},
		cpe.Resolve("node.js", "20"))
	assert.Equal(t, []string{"cpe:2.3:a:elastic:elasticsearch:7.10:*:*:*:*:*:*:*"},
		cpe.Resolve("elasticsearch", "7.10"))
}

// A version no vendor ships at any granularity still emits nothing when the
// product has several vendors — rule 3 is unchanged, and widening rule 1 did
// not turn silence into a guess. (The component-boundary property of the
// prefix probe itself is tested in carries_internal_test.go, against a
// synthetic version list: the real dictionary has shipped so many versions
// that a boundary assertion there passes for the wrong reason.)
func TestResolve_UnshippedVersionsStillEmitNothing(t *testing.T) {
	assert.Empty(t, cpe.Resolve("kubernetes", "1.29"))
	assert.Empty(t, cpe.Resolve("server", "3.2.1"))
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
