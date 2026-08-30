#!/usr/bin/env bash
# Fails when the agent-facing docs cite a repo path, first-party identifier, or Go
# version that no longer matches the tree. Stale docs produce confident-but-wrong
# AI review findings, so this runs on every PR that touches the docs or the source
# they cite.
set -euo pipefail
cd "$(dirname "$0")/.."

docs=(ARCHITECTURE.md DEVELOPMENT.md AGENTS.md)
while IFS= read -r f; do docs+=("$f"); done < <(find .agents/skills -name SKILL.md 2>/dev/null)

fail=0
note() { printf '%s\n' "$1" >&2; fail=1; }

# 1. Go version. Compare on major.minor; go.mod may be "1.25" or "1.25.8".
ver=$(awk '/^go /{print $2; exit}' go.mod)
case "$ver" in *.*.*) want=${ver%.*};; *) want=$ver;; esac
grep -qF "$ver" DEVELOPMENT.md 2>/dev/null || note "DEVELOPMENT.md does not cite go.mod version $ver"
# read -r, not $(...): "Go 1.24" contains a space and would word-split.
while IFS= read -r v; do
  case "$v" in *"$want"*) ;; *) note "stale Go version '$v' (go.mod: $ver)";; esac
done < <(grep -ohE 'Go 1\.[0-9]+' "${docs[@]}" 2>/dev/null | sort -u)

for doc in "${docs[@]}"; do
  [ -f "$doc" ] || continue

  # 2. Backticked repo paths must exist. Placeholders like <csp> are skipped.
  for p in $(grep -ohE '`(pkg|cmd|test|internal|scripts)/[A-Za-z0-9_./<>-]*`' "$doc" |
             tr -d '`' | grep -v '<' | sort -u); do
    [ -e "${p%/}" ] || note "$doc: path does not exist: $p"
  done

  # 3. Backticked first-party identifiers must resolve. capmodel.* is deliberately
  #    excluded -- ARCHITECTURE.md section 8 documents it before the repo imports it.
  for sym in $(grep -ohE '`(pipeline|plugin|ratelimit|store|output|model)\.[A-Z][A-Za-z0-9_]*`' "$doc" |
               tr -d '`' | sort -u); do
    id=${sym##*.}
    # top-level decl | method, incl. generic receiver | member of a const(/var( block
    grep -rqE "^(func|type|var|const) +$id\b|^func +\([^)]*\) *$id\b|^[[:space:]]+$id([[:space:]]|,|=)" \
      "pkg/${sym%%.*}/" 2>/dev/null || note "$doc: unresolved identifier: $sym"
  done
done

[ "$fail" -eq 0 ] || { echo "FAIL: doc references drifted from source" >&2; exit 1; }
echo "OK: all doc references resolve"
