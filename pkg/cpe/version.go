package cpe

import "strings"

// NormalizeVersion reduces an observed version string to the dotted numeric
// prefix a CPE version component can carry, and returns "" when there is no
// usable version.
//
//	1.25.3-alpine     -> 1.25.3
//	1.18.0-6ubuntu14  -> 1.18.0
//	v3.5.9            -> 3.5.9
//	15.4              -> 15.4
//	latest            -> ""
//	sha256:abc123     -> ""
//
// Distro and variant suffixes are dropped, never relocated to target_sw: the
// CPE shape is fixed by the criteria form, and the version is the only
// component derived from observed data. A version must have at least a major
// component to emit, so a tag with no leading digit yields nothing.
func NormalizeVersion(raw string) string {
	v := strings.TrimSpace(raw)

	// A colon anywhere means the string is not a plain version — a digest
	// (sha256:abc123) or some compound identifier. Distrust the whole value
	// rather than silently truncating it to the part before the colon, which
	// would turn "1.2:3" into a confident "1.2".
	if strings.ContainsRune(v, ':') {
		return ""
	}

	v = strings.TrimPrefix(v, "v")

	if v == "" || !isDigit(rune(v[0])) {
		return ""
	}

	// Take the leading run of digits and dots.
	end := 0
	for end < len(v) && (isDigit(rune(v[end])) || v[end] == '.') {
		end++
	}
	v = v[:end]

	// A trailing dot is a separator, not part of the version.
	v = strings.TrimRight(v, ".")
	if v == "" {
		return ""
	}
	return v
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }
