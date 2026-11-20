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
		defer gz.Close()
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

// ResolveVendors returns the CPE vendor strings that identify the given product
// at the given version, sorted, or an empty slice when the pair cannot be
// resolved unambiguously.
//
// The observed version selects the vendor:
//
//  1. If any live vendors carry exactly that version, return them — usually
//     exactly one.
//  2. Otherwise, if the product has exactly one vendor, return it. The version
//     is simply newer than the snapshot; the identification is still sound.
//  3. Otherwise return nothing. With several vendors and no version evidence
//     there is no basis on which to choose, and guessing produces a
//     confidently wrong CPE, which resolves against the wrong CVE set.
//
// There is no vendor-count threshold: the version, not the vendor count, is
// what discriminates.
func ResolveVendors(product, version string) []string {
	byVendor := load()[product]
	if len(byVendor) == 0 {
		return nil
	}

	var carrying []string
	for vendor, versions := range byVendor {
		if containsVersion(versions, version) {
			carrying = append(carrying, vendor)
		}
	}
	if len(carrying) > 0 {
		sort.Strings(carrying)
		return carrying
	}

	if len(byVendor) == 1 {
		for vendor := range byVendor {
			return []string{vendor}
		}
	}
	return nil
}

// containsVersion reports whether versions holds version exactly. The generator
// writes each vendor's versions sorted, so this is a binary search.
func containsVersion(versions []string, version string) bool {
	if version == "" {
		return false
	}
	i := sort.SearchStrings(versions, version)
	return i < len(versions) && versions[i] == version
}

// TableSize returns the number of distinct products in the generated table.
func TableSize() int {
	return len(load())
}
