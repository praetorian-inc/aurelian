package cpe

import "strings"

// NormalizeVersion reduces an observed version string to the dotted numeric
// prefix a CPE version component can carry, and returns "" when there is no
// usable version.
//
//	1.25.3-alpine          -> 1.25.3
//	1.18.0-6ubuntu14       -> 1.18.0
//	v3.5.9                 -> 3.5.9
//	15.4                   -> 15.4
//	jdk-25.0.5.1+2         -> 25.0.5.1
//	1:11.8.9+maria~ubu2404 -> 11.8.9
//	latest                 -> ""
//	sha256:abc123          -> ""
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
	//
	// The one exception is a Debian/RPM epoch: a leading run of digits, one
	// colon, then the version. mariadb:11 ships
	// MARIADB_VERSION=1:11.8.9+maria~ubu2404 and is lost without this. The
	// exception is deliberately narrow — exactly one colon, everything before
	// it a digit — so "1.2:3", "1:2:3", "v1:2.3" and "sha256:abc" all stay
	// rejected. It runs before the "v" trim so a prefix cannot smuggle a
	// non-epoch colon through.
	if strings.ContainsRune(v, ':') {
		epoch, rest, _ := strings.Cut(v, ":")
		if !isEpoch(epoch) || strings.ContainsRune(rest, ':') {
			return ""
		}
		v = rest
	}

	// Distribution prefixes on a Java version. Adoptium and the images built
	// on it report JAVA_VERSION=jdk-25.0.5.1+2; the version behind the prefix
	// resolves against the dictionary, so dropping the whole value over four
	// leading characters loses a real emission. Longest first, so "openjdk-"
	// is not left with a stray "open".
	for _, prefix := range []string{"openjdk-", "jdk-"} {
		if strings.HasPrefix(v, prefix) {
			v = v[len(prefix):]
			break
		}
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

// isEpoch reports whether s is a non-empty run of digits — the only thing
// allowed to sit before a colon in an observed version.
func isEpoch(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isDigit(r) {
			return false
		}
	}
	return true
}
