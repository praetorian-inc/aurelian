package cpe

import "strings"

// minFallbackComponents is the floor on TRUNCATION: the fallback will not
// shorten an observed version to fewer than two dotted components.
//
// It is not a floor on observation. A version that arrives with one component
// is tried as given — that is what tier 1 and tier 2 already emit, and the
// fallback must not narrow them.
//
// The floor exists because a bare major fabricates inventory. Measured:
//
//	rabbitmq 3.13.7 -> 3.13 (no entry) -> 3 => broadcom:rabbitmq:3 AND
//	                                          voxpupuli:rabbitmq:3, a PUPPET MODULE
//	influxdb 2.7.12 -> 2.7  (no entry) -> 2 => influxdata:influxdb:2, too coarse to mean anything
//
// voxpupuli is already named as an anti-goal in this repo's integration
// fixture. Its comment states why: the decision to emit every sibling vendor
// is safe only because homonyms are capped at versions that will not appear in
// a container tag, and "a resolution rule loosened to reach homonyms would
// fabricate inventory". Walking to a bare major is that loosening.
//
// What this costs is products whose dictionary versions ARE bare majors —
// PostgreSQL 15, InfluxDB 2. Those are not lost: the image tag path reads them
// independently (postgres:15 -> "15"), so the two signals are complementary.
const minFallbackComponents = 2

// ResolveBestEffort resolves product at the most precise version the CPE
// dictionary will accept, and reports which version that was.
//
// NVD's dictionary lags current patch releases. An image config reports the
// exact version a container runs, and for over half of the most common images
// that exact version has no dictionary row while a shorter prefix of it does:
// python 3.11.18 resolves nothing, python 3.11 resolves. Without this, a more
// precise observation would produce a smaller inventory than a vaguer one.
//
// The returned precision is the version actually used. It is never empty when
// cpes is non-empty, and a caller that observed a longer version can compare
// the two to record that the emission was truncated. That distinction matters
// downstream: cpe:2.3:a:python:python:3.11 matches every 3.11.x CVE, including
// ones the observed 3.11.18 has already been patched for.
//
// Conceding version precision while preserving vendor correctness is the trade
// this design already made for minor-only observations; this extends the same
// rule from a minor-only observation to a minor-only fallback.
func ResolveBestEffort(product, version string) (cpes []string, precision string) {
	if product == "" || version == "" {
		return nil, ""
	}

	for v := version; v != ""; v = truncateComponent(v) {
		if resolved := Resolve(product, v); len(resolved) > 0 {
			return resolved, v
		}
	}
	return nil, ""
}

// truncateComponent drops the last dotted component, or returns "" when doing
// so would fall below the floor or leave nothing.
func truncateComponent(v string) string {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return ""
	}
	shorter := v[:i]
	if strings.Count(shorter, ".")+1 < minFallbackComponents {
		return ""
	}
	return shorter
}
