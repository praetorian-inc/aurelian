#!/usr/bin/env bash
# Asserts every repo path and Go identifier cited in the agent-facing docs still
# exists, and that the Go version cited matches go.mod. Docs that rot silently
# produce confident-but-wrong AI review findings, so this runs on every PR.
set -euo pipefail

cd "$(dirname "$0")/.."

DOCS=(ARCHITECTURE.md DEVELOPMENT.md AGENTS.md)
while IFS= read -r f; do DOCS+=("$f"); done < <(find .agents/skills -name 'SKILL.md' 2>/dev/null)

fail=0
note() { printf '%s\n' "$1" >&2; fail=1; }

# 1. Go version must match go.mod
gomod_ver=$(awk '/^go /{print $2; exit}' go.mod)
if ! grep -qF "$gomod_ver" DEVELOPMENT.md 2>/dev/null; then
  note "DEVELOPMENT.md does not cite go.mod version $gomod_ver"
fi
# Read line-by-line: the match "Go 1.24" contains a space, so an unquoted
# command substitution would split it into "Go" and "1.24" and report twice --
# and the bare "Go" token can never match the go.mod version, so every doc
# citing any Go version would fail the gate.
while IFS= read -r bad; do
  [ -n "$bad" ] || continue
  # Compare on major.minor. go.mod may be two-part ("1.25") or three-part
  # ("1.25.8"); ${v%.*} on a two-part value yields "1", which would match any
  # 1.x and silently disable this check.
  case "$gomod_ver" in *.*.*) want="${gomod_ver%.*}";; *) want="$gomod_ver";; esac
  case "$bad" in *"$want"*) ;; *) note "stale Go version '$bad' (go.mod: $gomod_ver)";; esac
done < <(grep -ohE 'Go 1\.[0-9]+' "${DOCS[@]}" 2>/dev/null | sort -u)

# 2. Every backticked repo path must exist
for doc in "${DOCS[@]}"; do
  [ -f "$doc" ] || continue
  for p in $(grep -ohE '`(pkg|cmd|test|internal|scripts)/[A-Za-z0-9_./<>-]*`' "$doc" \
             | tr -d '`' | grep -v '<' | sort -u); do
    [ -e "${p%/}" ] || note "$doc: path does not exist: $p"
  done
done

# 3. Every backticked pkg-qualified identifier must resolve.
#    First-party prefixes only. Third-party types that ARCHITECTURE.md documents as a
#    migration target (notably capmodel.*, see ARCHITECTURE.md section 8 Direction) are
#    deliberately NOT checked -- they are documented before they are imported. The
#    backtick anchors the alternation, so `capmodel.X` does not match `model\.`.
for doc in "${DOCS[@]}"; do
  [ -f "$doc" ] || continue
  for sym in $(grep -ohE '`(pipeline|plugin|ratelimit|store|output|model)\.[A-Z][A-Za-z0-9_]*`' "$doc" \
               | tr -d '`' | sort -u); do
    pkgname="${sym%%.*}"; ident="${sym##*.}"
    # Three shapes must resolve:
    #   1. top-level  func/type/var/const Name ...
    #   2. methods    func (r *Recv) Name(...)  and generic receivers func (r *R[T, K]) Name
    #   3. block members  const ( ... \n\tName Type = ... )  -- an indented member of a
    #      const(/var( block. Without this a real block constant is reported unresolved.
    grep -rqE "^(func|type|var|const) +${ident}\b|^func +\([^)]*\) *${ident}\b|^[[:space:]]+${ident}([[:space:]]|,|=)" \
      "pkg/${pkgname}/" 2>/dev/null || note "$doc: unresolved identifier: $sym"
  done
done

if [ "$fail" -ne 0 ]; then
  echo "FAIL: doc references drifted from source" >&2
  exit 1
fi
echo "OK: all doc references resolve"
