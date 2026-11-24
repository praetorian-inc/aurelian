package cpe_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
)

var guardKeyRegex = regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

// Resolve is the only way a CPE string enters aurelian's output: pkg/software
// constructs output.Technology in exactly one place, from Resolve's return
// value, for every resource type and every cloud. So the guarantee guard
// depends on — that no emitted key can fail model.NewTechnology — is a
// property of this function alone and does not need re-proving per provider.
//
// Fuzzing it is how that property is checked against inputs nobody wrote a
// case for. Products and versions reach Resolve from registry tags, image
// config environment variables and cloud API fields, none of which aurelian
// controls.
func FuzzResolve_NeverEmitsAKeyGuardWouldReject(f *testing.F) {
	for _, tc := range []struct{ product, version string }{
		{"nginx", "1.25.3"},
		{"notepad++", "8.9.6.4"},
		{"1c:enterprise", "8.3.13"},
		{".net", "8.0.34"},
		{"http_server", "2.4.71"},
		{"openjdk", "25.0.5.1"},
		{"node.js", "20.20.2"},
		// Shapes that have broken an emitter before: a colon that survived
		// normalisation, wildcard characters, and escape sequences.
		{"nginx", "1.25.5:extra:fields"},
		{"nginx", "*"},
		{"php", "?"},
		{"ruby", `3.3.14\:*\:*`},
		// Found by this fuzzer: a literal backslash is quoted twice and binds
		// to a component NVD never publishes, past keyRegex (which sees no
		// colon). Reachable through Resolve's public API, though not through
		// aurelian, whose NormalizeVersion strips backslashes first.
		{"r", `\`},
		{"", ""},
	} {
		f.Add(tc.product, tc.version)
	}

	f.Fuzz(func(t *testing.T, product, version string) {
		for _, c := range cpe.Resolve(product, version) {
			if !guardKeyRegex.MatchString(c) {
				t.Fatalf("Resolve(%q, %q) emitted %q, which guard's "+
					"model.NewTechnology rejects", product, version, c)
			}
			// A double backslash is a component escaped twice; NVD never
			// publishes one, so it would match no CVE.
			if strings.Contains(c, `\\`) {
				t.Fatalf("Resolve(%q, %q) emitted a double-escaped component: %q",
					product, version, c)
			}
		}
	})
}
