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
// Returning several vendors for one product/version is deliberate, not a gap to
// close. DECIDED 2026-11-23, after an attempt to alias them away:
//
// NVD's deprecated/deprecatedBy metadata is the mechanism for a vendor
// migration, and the generator already follows it — pivotal_software:redis is
// dropped that way, all 27 entries flagged. NVD never applied it to redislabs:
// 368 live redislabs:redis rows sit beside 643 live redis:redis rows, so the
// dictionary asserts both vendors are current and there is no pointer to follow.
//
// It moved the CVE filing without deprecating the dictionary rows. redislabs
// carries 22 CVEs published 2013 through Sept 2021; redis carries 46 from 2021
// onward. A redis:6.2.6 container sits on that boundary, so collapsing to one
// vendor silently drops an era of CVEs. A missing match is invisible; a CPE that
// matches nothing is inert.
//
// Aliasing also needs the table it would justify: a collapse must know that
// hashicorp:consul and makandra:consul are NOT the same software. Of 31
// reachable products 14 never collide at all, and the only collisions reaching
// versions still in production — redis 6.2.6 and MySQL 5.6.36 — are true alias
// pairs. Every homonym collision (jenkins:kubernetes, makandra:consul,
// mysqljs:mysql, tibco:vault) is capped at a 2004-2018 version that will not
// appear in a container tag or a Lambda runtime.
//
// That cap is the premise, and it is asserted rather than assumed: see
// forbidden_cpe_substrings in test/terraform/aws/recon/technology-emission/.
//
// Downstream precondition: guard's CPE-to-CVE matcher must key on vendor. One
// that matched on product and version alone would give both siblings edges and
// double every finding for that software.
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
