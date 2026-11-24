// Package cpe turns an observed (product, version) pair into CPE 2.3 strings.
//
// It is standalone: it imports nothing else from aurelian, takes plain strings
// and returns plain strings, so the caller wraps the result into whatever model
// it needs. The vendor table is generated from the NVD CPE dictionary and
// committed, so `go build` and `go test` never reach the network — only an
// explicit `go generate` does.
package cpe

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	_ "embed"
)

//go:generate go run ./gen

//go:embed cpemap.json.gz
var cpemapGz []byte

// vendorTable is product -> vendor -> sorted versions, distilled from the live
// application entries of the whole NVD dictionary. There is deliberately no
// product allowlist: scope is enforced at detection, never by truncating this
// table.
type vendorTable map[string]map[string][]string

var (
	loadOnce sync.Once
	table    vendorTable
	loadErr  error
)

func load() vendorTable {
	loadOnce.Do(func() {
		gz, err := gzip.NewReader(bytes.NewReader(cpemapGz))
		if err != nil {
			loadErr = fmt.Errorf("open embedded cpemap: %w", err)
			return
		}
		defer func() { _ = gz.Close() }()
		if err := json.NewDecoder(gz).Decode(&table); err != nil {
			loadErr = fmt.Errorf("decode embedded cpemap: %w", err)
		}
	})
	if loadErr != nil {
		// The table is embedded at build time, so a failure here means the
		// committed artifact is corrupt — not a runtime condition a caller can
		// recover from or should have to branch on.
		panic(loadErr)
	}
	return table
}

// ResolveVendors returns every CPE vendor string the dictionary lists for the
// given product, sorted. The version is deliberately not a parameter.
//
// This replaced a rule in which the observed version selected the vendor
// (vendors carrying that version won; failing that, a sole vendor was used;
// failing that, nothing was emitted). That rule was measured against the live
// NVD CVE corpus on 2026-11-24 — every CVE referencing each of 19 products
// downloaded, and NVD's range semantics evaluated offline against 30 real
// observed versions — and it was wrong in both directions:
//
//   - It MISSED CVEs, because a product's CVEs are filed under several vendors.
//     http_server 2.4.71 matched 11 of its 15 CVEs when only apache was
//     emitted; openjdk matched 2 of 13.
//   - It FABRICATED CVEs, because when the dictionary did not carry the
//     observed version the caller truncated it until something resolved.
//     node.js 20.20.2 truly matches 1 CVE; the 20.20 emitted in its place
//     matches 12.
//
// Emitting every vendor costs nothing in CVE accuracy, because **the version
// does the filtering, not the vendor**. A homonym vendor never shipped the
// observed version, so its CPE matches no CVE and is inert — it costs a node.
// Measured, rabbitmq 3.13.7 under all five of its dictionary vendors yields
// exactly the one CVE that truly affects it, voxpupuli included.
//
// That is why the old sole-vendor and version-carrying rules are gone, along
// with the dotted-prefix version match that backed them. Over 30 observations
// the change moved precision 0.940 -> 1.000 and recall 0.849 -> 0.906.
//
// What it does NOT fix: vendor names that appear in CVE configurations but not
// in the CPE dictionary at all. sun:openjdk has zero dictionary entries yet is
// cited by 11 live CVEs, and php_group:php, python_software_foundation:python,
// yukihiro_matsumoto:ruby and nginx:nginx are the same shape — deprecated
// predecessors that CVE records still reference. The generator drops a
// deprecated record's own vendor and keeps only its successor's, which is what
// loses them. Retaining both takes recall to 1.000; see pkg/cpe/gen/distill.go.
//
// Downstream precondition, unchanged: guard's CPE-to-CVE matcher must match on
// the vendor field. NVD's cpeMatch criteria carry it, so a matcher built on
// that data gets this for free. A matcher using a wildcard vendor would give
// every sibling an edge to the same CVE and double every finding.
func ResolveVendors(product string) []string {
	byVendor := load()[product]
	if len(byVendor) == 0 {
		return nil
	}
	out := make([]string, 0, len(byVendor))
	for vendor := range byVendor {
		out = append(out, vendor)
	}
	sort.Strings(out)
	return out
}

func TableSize() int {
	return len(load())
}
