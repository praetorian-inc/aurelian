package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Table accumulates product -> set(vendor) across feed chunks, from both
// sources: the CPE dictionary (names that exist) and the CVE corpus (names
// that are used). It is a union — see HarvestCVEChunk for why neither source
// alone is sufficient.
//
// Versions are deliberately not recorded. They were, until the resolution rule
// was measured against the live CVE corpus on 2026-11-24: NVD attaches CVEs to
// version RANGES, so a dictionary version set can neither confirm nor exclude
// an observed version, and ResolveVendors no longer takes a version at all.
// Carrying them made the artifact ten times larger than its only consumer
// needs, and would have forced this file to invent version data for every
// vendor the CVE pass contributes.
type Table = map[string]map[string]struct{}

// record notes that `product` is published under `vendor`. Both sources funnel
// through it so the table can never acquire two spellings of the same entry.
func record(into Table, product, vendor string) {
	vendors, ok := into[product]
	if !ok {
		vendors = map[string]struct{}{}
		into[product] = vendors
	}
	vendors[vendor] = struct{}{}
}

// maxDeprecationDepth bounds the deprecatedBy walk. NVD's longest observed
// chain is igor_sysoev -> nginx -> f5 (two hops); the bound only has to stop a
// cycle or a pathological chain, not to be tight.
const maxDeprecationDepth = 16

type nvdChunk struct {
	Products []struct {
		CPE struct {
			CPEName      string `json:"cpeName"`
			Deprecated   bool   `json:"deprecated"`
			DeprecatedBy []struct {
				CPEName string `json:"cpeName"`
			} `json:"deprecatedBy"`
		} `json:"cpe"`
	} `json:"products"`
}

// DeprecationRecord is one dictionary name's deprecation status and the names
// that superseded it.
type DeprecationRecord struct {
	Deprecated bool
	Successors []string
}

// DeprecationIndex maps a CPE name to its deprecation record, across the whole
// feed rather than one chunk.
type DeprecationIndex = map[string]DeprecationRecord

// IndexChunk records one chunk's deprecation edges into idx. The generator runs
// this over every chunk before distilling, because a rename chain spans chunks:
// igor_sysoev:nginx sits in chunk 1 while the nginx:nginx records it points at
// span chunks 1-8, and nginx:nginx has no live record anywhere. Resolving
// against one chunk alone stops early and records a deprecated vendor as live.
func IndexChunk(body []byte, idx DeprecationIndex) error {
	var chunk nvdChunk
	if err := json.Unmarshal(body, &chunk); err != nil {
		return fmt.Errorf("parse cpe chunk: %w", err)
	}
	for _, p := range chunk.Products {
		idx[p.CPE.CPEName] = DeprecationRecord{
			Deprecated: p.CPE.Deprecated,
			Successors: successorsOf(p.CPE.DeprecatedBy),
		}
	}
	return nil
}

// DistillChunk parses one NVD CPE dictionary chunk (or one /cpes/2.0 REST
// response — they share a schema) and accumulates its live application entries
// into `into` as product -> set(vendor), resolving deprecations against that
// chunk alone.
//
// Deprecated records are not merely dropped. NVD records the rename chain in
// `deprecatedBy`, so a deprecated record contributes its *successor's* vendor
// and version under its own product key: a lookup on the old product name still
// resolves to the current vendor. The walk is transitive (igor_sysoev -> nginx
// -> f5) and bounded against cycles.
//
// Only `part == "a"` entries are kept; operating systems and hardware are out
// of scope for this design.
//
// Use DistillChunkWithIndex when the chain may leave the chunk, which it does
// in the real feed.
func DistillChunk(body []byte, into Table) error {
	return DistillChunkWithIndex(body, into, nil)
}

// DistillChunkWithIndex is DistillChunk with deprecation chains resolved
// against idx — an index of the whole feed, built by IndexChunk — falling back
// to this chunk's own records for names idx does not carry.
func DistillChunkWithIndex(body []byte, into Table, idx DeprecationIndex) error {
	var chunk nvdChunk
	if err := json.Unmarshal(body, &chunk); err != nil {
		return fmt.Errorf("parse cpe chunk: %w", err)
	}

	local := make(DeprecationIndex, len(chunk.Products))
	for _, p := range chunk.Products {
		local[p.CPE.CPEName] = DeprecationRecord{
			Deprecated: p.CPE.Deprecated,
			Successors: successorsOf(p.CPE.DeprecatedBy),
		}
	}

	lookup := func(name string) (DeprecationRecord, bool) {
		if idx != nil {
			if rec, ok := idx[name]; ok {
				return rec, true
			}
		}
		rec, ok := local[name]
		return rec, ok
	}

	// resolve walks to the live terminal names a deprecated record stands for.
	// A successor the index does not carry is treated as live: there is no
	// evidence against it, and the feed's own live record will confirm it.
	var resolve func(name string, depth int, seen map[string]bool) []string
	resolve = func(name string, depth int, seen map[string]bool) []string {
		if depth > maxDeprecationDepth || seen[name] {
			return nil
		}
		seen[name] = true
		rec, ok := lookup(name)
		if !ok || !rec.Deprecated {
			return []string{name}
		}
		var out []string
		for _, s := range rec.Successors {
			out = append(out, resolve(s, depth+1, seen)...)
		}
		return out
	}

	for _, p := range chunk.Products {
		_, product, _, _, ok := splitCPE(p.CPE.CPEName)
		if !ok {
			continue
		}

		names := []string{p.CPE.CPEName}
		if p.CPE.Deprecated {
			names = resolve(p.CPE.CPEName, 0, map[string]bool{})
		}

		for _, name := range names {
			_, _, vendor, _, ok := splitCPE(name)
			if !ok {
				continue
			}
			record(into, product, vendor)
		}
	}
	return nil
}

func successorsOf(by []struct {
	CPEName string `json:"cpeName"`
}) []string {
	out := make([]string, 0, len(by))
	for _, d := range by {
		if d.CPEName != "" {
			out = append(out, d.CPEName)
		}
	}
	return out
}

// splitCPE splits a CPE 2.3 formatted string, honouring backslash escapes, and
// returns its part, product, vendor and version. ok is false unless the string
// is a well-formed 13-component application entry.
//
// The returned components are **unescaped literals**: NVD publishes
// `notepad\+\+`, and the table keys on `notepad++`. Callers of ResolveVendors
// pass a product as they spell it and should never have to know CPE's quoting
// rules; assemble re-applies the escaping when it binds the formatted string.
// Storing the escaped spelling would make the literal miss the table and the
// escaped spelling bind to a double-escaped string NVD never publishes.
func splitCPE(name string) (part, product, vendor, version string, ok bool) {
	c := splitEscaped(name)
	if len(c) != 13 || c[0] != "cpe" || c[1] != "2.3" || c[2] != "a" {
		return "", "", "", "", false
	}
	return c[2], unquote(c[4]), unquote(c[3]), unquote(c[5]), true
}

// unquote removes CPE 2.3 formatted-string backslash escaping, turning
// `notepad\+\+` into `notepad++`. A trailing lone backslash is dropped.
func unquote(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// splitEscaped splits on ':' but not on a ':' preceded by an odd number of
// backslashes — CPE 2.3 escapes literal colons that way.
func splitEscaped(s string) []string {
	var out []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			b.WriteRune(r)
			escaped = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	out = append(out, b.String())
	return out
}
