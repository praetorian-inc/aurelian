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
	"sync"

	_ "embed"
)

//go:generate go run ./gen

//go:embed cpemap.json.gz
var cpemapGz []byte

// vendorTable is product -> sorted vendors, distilled from two NVD corpora:
// the CPE dictionary's live application entries (names that exist) and the CVE
// feeds' applicability criteria (names that are used). There is deliberately
// no product allowlist: scope is enforced at detection, never by truncating
// this table.
type vendorTable map[string][]string

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
// the change moved precision 0.940 -> 1.000 and recall 0.849 -> 0.906; adding
// the CVE corpus as a second vendor source then took recall to 1.000.
//
// The last 9.4% of recall was a different problem, and it is fixed in the
// generator rather than here. Ten vendor spellings are cited by live CVE
// configurations and carry NO CPE dictionary record at all — sun:openjdk is
// cited by 17 CVEs and does not exist in the dictionary, deprecated or
// otherwise, and php_group:php, python_software_foundation:python,
// yukihiro_matsumoto:ruby and nginx:nginx are the same shape. No resolution
// rule over a dictionary-only table could reach them. The generator therefore
// distils from both corpora: the dictionary for names that exist, the CVE
// feeds for names that are used. See pkg/cpe/gen/cve.go. That took measured
// recall to 1.000.
//
// Downstream precondition, unchanged: guard's CPE-to-CVE matcher must match on
// the vendor field. NVD's cpeMatch criteria carry it, so a matcher built on
// that data gets this for free. A matcher using a wildcard vendor would give
// every sibling an edge to the same CVE and double every finding.
func ResolveVendors(product string) []string {
	vendors := load()[product]
	if len(vendors) == 0 {
		return nil
	}
	// The generator writes these sorted; copy so a caller cannot mutate the
	// process-wide table through the returned slice.
	out := make([]string, len(vendors))
	copy(out, vendors)
	return out
}

func TableSize() int {
	return len(load())
}
