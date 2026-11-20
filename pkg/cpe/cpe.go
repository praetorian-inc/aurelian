package cpe

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

// keyRegex is guard's technology key regex: a CPE 2.3 formatted string of
// exactly thirteen colon-separated components, none of them empty. Every
// emitted string is checked against it, so nothing aurelian emits can fail
// guard's model.NewTechnology.
var keyRegex = regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

// Resolve returns the CPE 2.3 strings identifying the given product at the
// given version — zero, one, or one per vendor that carries that version.
//
// The output is *criteria-shaped*, matching NVD's own applicability statements:
// `part:vendor:product:<observed version>` with `*` in all seven remaining
// components. NVD expands `*` to cover the `-` ("not applicable") dictionary
// names, so no choice between `-` and `*` is made here. Because NVD publishes a
// precomputed matches[] for each criteria, an emission carrying an exact
// version resolves without the consumer implementing range logic.
//
// Resolve returns plain strings rather than a model type: pkg/cpe imports
// nothing from aurelian, so the caller does the wrapping.
//
// An input that cannot be resolved unambiguously emits nothing. Silence is the
// correct failure mode — a mis-vendored CPE resolves against the wrong CVE set,
// which is worse than no row.
func Resolve(product, version string) []string {
	if product == "" || version == "" {
		return nil
	}

	vendors := ResolveVendors(product, version)
	if len(vendors) == 0 {
		return nil
	}

	out := make([]string, 0, len(vendors))
	for _, vendor := range vendors {
		c, ok := assemble(vendor, product, version)
		if !ok {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// assemble builds one criteria-shaped CPE with knqyf263/go-cpe — the library
// guard parses with, so the output is guaranteed to survive its model.
func assemble(vendor, product, version string) (string, bool) {
	wfn := common.NewWellFormedName() // every component defaults to ANY -> "*"
	if err := wfn.Set(common.AttributePart, "a"); err != nil {
		return "", false
	}
	for attr, value := range map[string]string{
		common.AttributeVendor:  vendor,
		common.AttributeProduct: product,
		common.AttributeVersion: version,
	} {
		if err := wfn.Set(attr, quote(value)); err != nil {
			return "", false
		}
	}

	fs := naming.BindToFS(wfn)
	if !keyRegex.MatchString(fs) {
		// A value carrying a colon (an RDS "8.0.mysql_aurora.3.04.0" style
		// string that escaped normalisation, say) binds to a quoted colon and
		// yields more than thirteen components. Emit nothing rather than a
		// string guard will reject.
		return "", false
	}
	if _, err := naming.UnbindFS(fs); err != nil {
		return "", false
	}
	return fs, true
}

// quote backslash-escapes the punctuation a well-formed name requires to be
// quoted. `_` is permitted bare, and `*`/`?` are wildcards we never want
// interpreted inside a literal vendor, product or version.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, r := range s {
		if unicode.IsPunct(r) && r != '_' {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
