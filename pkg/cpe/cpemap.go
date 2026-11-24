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
	"strings"
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
//  1. If any live vendors carry that version, return them — usually exactly
//     one. A vendor carries a version either exactly, or as a dotted prefix of
//     a version it publishes: a vendor shipping 3.12.0 through 3.12.7 is
//     evidence for an observed "3.12". See carriesVersion.
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
// reachable products 14 never collide at all, and most homonym collisions
// (jenkins:kubernetes, makandra:consul, mysqljs:mysql, tibco:vault) are capped
// at a 2004-2018 version that will not appear in a container tag or a Lambda
// runtime. That cap is asserted rather than assumed: see
// forbidden_cpe_substrings in test/terraform/aws/recon/technology-emission/.
//
// The cap is not total, and the cost of emitting both is not uniform. Measured
// against the NVD CVE API:
//
//   - redis 6.2.6 is free. redislabs:redis:6.2.6 matches 0 CVEs against
//     redis:redis:6.2.6's 22, and across all versions the two vendors' CVE sets
//     (22 and 46) do not intersect at all. The extra CPE is inert: it costs a
//     node and matches nothing.
//   - mysql 5.6.36 is not. mysql:mysql is a homonym, not an alias — its two
//     CVEs at that version are CVE-2009-2942 (the mysql-ocaml bindings) and
//     CVE-2017-12419 (MantisBT, a PHP bug tracker), neither of which is MySQL
//     server, against oracle:mysql:5.6.36's 215. It carries exactly one version
//     for this product where oracle carries 674, which is the shape of a junk
//     attribution. ResolveVendors emits it today; see
//     TestResolveVendors_MySQLHomonymReachesAProductionVersion.
//
// So emit-both has one measured counterexample at a version real software runs.
// It is two fabricated CVEs on one product, judged cheaper than dropping an era
// of real ones — but it is a cost, not a free hedge, and a future narrowing
// rule should start here rather than with redis.
//
// Downstream precondition: guard's CPE-to-CVE matcher must match the vendor
// field. NVD's cpeMatch criteria carry the vendor, so a matcher built on that
// data gets this for free — but NVD's own API also offers virtualMatchString,
// which accepts a wildcard vendor. Reaching for it is the natural move for
// someone who has just concluded that vendor spelling is unreliable, and it is
// what would give both siblings edges to the same CVE and double every finding.
func ResolveVendors(product, version string) []string {
	byVendor := load()[product]
	if len(byVendor) == 0 {
		return nil
	}

	var carrying []string
	for vendor, versions := range byVendor {
		if carriesVersion(versions, version) {
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

// carriesVersion reports whether a vendor's version list is evidence that the
// vendor ships the observed version — exactly, or at finer granularity.
//
// The exact case is the common one. The dotted-prefix case exists because the
// most-reported versions in this design are *less precise than the dictionary*.
// A Lambda runtime reports `python3.12`, never `python3.12.7`; a container tag
// reports `influxdb:1.8`, never `1.8.10`. NVD indexes the patch level, so an
// exact-only test finds nothing and rule 3 drops the whole observation — which
// is how the two commonest Lambda runtimes in existence, Python and Node.js,
// used to emit nothing at all.
//
// A vendor publishing 3.12.0 through 3.12.7 is real evidence that an observed
// "3.12" is theirs. What is lost is version precision, not vendor correctness:
// the emitted CPE names the right vendor and the right product, and carries the
// version actually observed. That is categorically different from naming a
// vendor the dictionary never associates with the product, which is the
// confidently-wrong output this design forbids.
//
// The trailing dot is what keeps this honest: "3.1" tests the prefix "3.1.",
// so it matches 3.1.4 and never 3.12.0.
//
// The generator writes each vendor's versions sorted, and a lexicographic sort
// puts every string sharing a prefix in one contiguous run, so both tests are
// binary searches.
func carriesVersion(versions []string, version string) bool {
	if version == "" {
		return false
	}
	if i := sort.SearchStrings(versions, version); i < len(versions) && versions[i] == version {
		return true
	}
	prefix := version + "."
	j := sort.SearchStrings(versions, prefix)
	return j < len(versions) && strings.HasPrefix(versions[j], prefix)
}

// TableSize returns the number of distinct products in the generated table.
func TableSize() int {
	return len(load())
}
