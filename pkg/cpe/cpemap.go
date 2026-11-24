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
	"slices"
	"sync"

	_ "embed"
)

//go:generate go run ./gen

//go:embed cpemap.json.gz
var cpemapGz []byte

// vendorTable is product -> sorted vendors, distilled from the CPE dictionary
// (names that exist) and the CVE feeds (names that are used). No product
// allowlist: scope is enforced at detection.
type vendorTable map[string][]string

// load decodes the embedded table once. A failure means the committed
// artifact is corrupt, not a runtime condition a caller can recover from, so
// it panics — and sync.OnceValue re-panics identically on every later call.
var load = sync.OnceValue(func() vendorTable {
	gz, err := gzip.NewReader(bytes.NewReader(cpemapGz))
	if err != nil {
		panic(fmt.Errorf("open embedded cpemap: %w", err))
	}
	defer func() { _ = gz.Close() }()

	var table vendorTable
	if err := json.NewDecoder(gz).Decode(&table); err != nil {
		panic(fmt.Errorf("decode embedded cpemap: %w", err))
	}
	return table
})

// ResolveVendors returns every vendor string NVD publishes the product under,
// sorted. The version is deliberately not a parameter: NVD matches CVEs on
// version ranges, so the version filters and the vendor does not. A homonym
// vendor never shipped the observed version, so its CPE matches no CVE.
//
// Measured against the live CVE corpus on 2026-11-24 over 30 observations,
// dropping the old "version selects the vendor, else truncate until the
// dictionary resolves" rule moved precision 0.940 -> 1.000 and recall
// 0.849 -> 1.000.
//
// Requires guard's CPE-to-CVE matcher to match on the vendor field; a wildcard
// vendor would give every sibling an edge to the same CVE.
func ResolveVendors(product string) []string {
	vendors := load()[product]
	if len(vendors) == 0 {
		return nil
	}
	// The generator writes these sorted; clone so a caller cannot mutate the
	// process-wide table through the returned slice.
	return slices.Clone(vendors)
}

func TableSize() int {
	return len(load())
}
