package cpe

import (
	"regexp"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

// keyRegex is guard's technology key regex: a CPE 2.3 formatted string of
// exactly thirteen colon-separated components, none of them empty. Every
// emitted string is checked against it, so nothing aurelian emits can fail
// guard's model.NewTechnology.
var keyRegex = regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

// Resolve returns the CPE 2.3 strings identifying the given product at the
// given version — one per vendor NVD publishes the product under, or none.
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

	vendors := ResolveVendors(product)
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
	if strings.Contains(fs, `\\`) {
		// A component that was already escaped gets quoted a second time: a
		// literal backslash in a version binds to `\\`. NVD publishes no such
		// name, so the key would satisfy guard's regex and still match no CVE.
		// keyRegex cannot catch this — a double backslash carries no colon.
		return "", false
	}
	if _, err := naming.UnbindFS(fs); err != nil {
		return "", false
	}
	return fs, true
}

// quote backslash-escapes every character a well-formed name requires to be
// quoted: everything outside [a-zA-Z0-9_].
//
// This deliberately does not use unicode.IsPunct, which classifies `+` as a
// symbol rather than punctuation and so left `notepad++` unescaped — NVD
// publishes `notepad\+\+`. The same gap covers `<=>|~$^`+"`"+`. BindToFS prints
// `.`, `-` and `_` bare again and keeps the rest escaped, which is what CPE
// 2.3's formatted string requires.
//
// `*` and `?` are escaped too: inside a literal vendor, product or version we
// never want them read as wildcards.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, r := range s {
		if !isUnquoted(r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isUnquoted(r rune) bool {
	return r == '_' ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}
