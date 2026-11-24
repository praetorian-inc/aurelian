package cpe_test

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_CriteriaShape(t *testing.T) {
	// Both spellings are emitted: f5 is the dictionary's live vendor, and
	// nginx:nginx is cited by CVE configurations that were never back-filled
	// after the F5 acquisition. The shape under test is the criteria form —
	// part:vendor:product:<observed version> with `*` in the other seven.
	assert.Equal(t, []string{
		"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
		"cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
	}, cpe.Resolve("nginx", "1.25.3"))
}

func TestResolve_EmitsNothingOnBadInput(t *testing.T) {
	assert.Empty(t, cpe.Resolve("nginx", ""))
	assert.Empty(t, cpe.Resolve("nginx", "1.2:3"))
	assert.Empty(t, cpe.Resolve("no_such_product_xyz", "1.0"))
	assert.Empty(t, cpe.Resolve("", "1.0"))
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
	//
	// Asserted per-CPE rather than as the whole set: vendor selection no
	// longer narrows by version, so this product resolves under every vendor
	// the dictionary lists for it. What this test is about is the escaping.
	got := cpe.Resolve("notepad++", "8.9.6.4")
	assert.Contains(t, got, `cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.9.6.4:*:*:*:*:*:*:*`)
	for _, c := range got {
		assert.Contains(t, c, `notepad\+\+`, "the product keeps NVD's escaped spelling")
		assert.NotContains(t, c, `\\`, "must never emit a double-escaped component")
	}

	// The escaped spelling is not an input a caller should have to supply, and
	// must not resolve to a double-escaped string.
	for _, c := range cpe.Resolve(`notepad\+\+`, "8.9.6.4") {
		assert.NotContains(t, c, `\\`, "must never emit a double-escaped component")
	}
}

func TestResolveVendors_ProductKeysAreUnescaped(t *testing.T) {
	assert.NotEmpty(t, cpe.ResolveVendors("notepad++"))
	// A product whose NVD spelling escapes a colon still keys on the literal.
	assert.NotEmpty(t, cpe.ResolveVendors("1c:enterprise"))
}

// A product whose punctuation needs one escape must not get two: `+` binds to
// `\+`, never `\\+`.
//
// This is not a ban on `\\` in general. That sequence is the correct CPE 2.3
// escaping of a literal backslash, and NVD publishes 280 part-`a` names
// containing one — `backpack\\crud`, the PHP namespace Backpack\CRUD, among
// them. None of the products below contains a backslash, which is why none of
// their emissions may carry `\\`.
func TestResolve_NeverDoubleEscapes(t *testing.T) {
	for _, p := range []string{"notepad++", "c++_compiler_classic", "sendmail+pro", "deslock+"} {
		for _, c := range cpe.Resolve(p, "1.0") {
			assert.NotContains(t, c, `\\`, "product %s", p)
			assert.Regexp(t, keyRegexForTest, c, "product %s", p)
		}
	}
}

var keyRegexForTest = regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)
