---
name: aurelian-code-review
description: Use when reviewing an Aurelian pull request. Covers the behavioral defect pass, the architecture invariant pass, and the principles pass for Go cloud recon code across AWS, Azure, GCP, and Kubernetes.
license: Apache-2.0
---

# Aurelian code review

Advisory. Technical feedback only. You do not approve or reject — the human reviewer
decides.

Two normative documents hold the rules. This skill does not restate them:

- `ARCHITECTURE.md` — Aurelian invariants, sections 1 through 11.
- `DEVELOPMENT.md` — Go craft and the three enforceable principles, sections 1 through 9.

Read both before reviewing. Cite them by section. Never paraphrase a rule into a
finding — a paraphrase drifts from the source and the author cannot contest it.

## Scope discipline

- Code review only. Do not demand new tests. Do not comment on coverage, missing
  tests, or test naming.
- No stylistic, formatting, or naming nits beyond the low-severity list below.
- Do not propose refactors outside the diff. Do not edit files. Do not push commits.
- Flag only what you can pin to a concrete file and line.
- Flag only what is observable in the diff.

Adjacent pre-existing issues are the one exception, and they are **not** findings. If
the diff leads you to a real problem in untouched code, put it in Notes, say it is
pre-existing and out of scope, and name the file. It does not count against the caps
and does not change the verdict. Two reasons: the observation is worth keeping as
backlog rather than discarding, and recording it separately stops it leaking into the
findings table where it would block a PR that did not cause it. If it genuinely blocks
this change — the diff cannot be correct until it is fixed — then it is in scope, and
it goes in the table as a finding like any other.

## Procedure

1. Read the PR title and body.
2. Read the diff.
3. Read each changed file **in full**. Never review a diff in isolation — the
   surrounding function decides whether a diff-local line is a defect.
4. Run the three passes below, in order.
5. Post one top-level comment. No inline comments.

Order matters. A behavioral defect outranks an invariant deviation, which outranks a
principle finding.

## Pass 1 — behavioral defects

Spend most of the budget here. These are review-only judgments: no document can state
them in advance because they depend on what the diff does.

**Every list in this pass is illustrative, not exhaustive.** The headings name the
classes of defect worth hunting; the bullets are the shapes seen most often in this
codebase. A defect that changes behaviour belongs in this pass whether or not it
matches a bullet. Do not treat a list as a checklist you can complete, and never
withhold a real finding because it is not enumerated.

### Intent

Does the change do what the PR body and the changed function names claim? Flag scope
creep beyond stated intent.

A PR body is a snapshot: authors push commits without rewriting it, so it is routinely
incomplete rather than wrong. Silence in the body is not a finding. Flag only when the
code **contradicts** a stated claim, or when work outside the stated scope carries real
risk. Never open a finding whose remedy is "update the PR description".

### Logic

- Off-by-one, wrong loop bounds, wrong slice indices.
- Filter loops that validate one slice then operate on the unfiltered one.
- Branches genuinely unreachable given the call graph. Check the `ARCHITECTURE.md` §11
  carve-outs first: blank imports, `init()` registration, registry and reflection
  dispatch, and CSP interface boundaries are load-bearing and are never dead code.

### Concurrency

- A closure capturing the wrong variable when the closure is created outside a `for`
  statement. The for-loop case is fixed by the language; closures built in other
  constructs still carry the risk.
- Two goroutines writing the same field with no synchronization.
- Cancellation dropped on a long-running call.
- A local variable shadowing an imported package name — `pipeline`, `context`,
  `errors`.

The rules behind these are `DEVELOPMENT.md` §4, which you have already read. Cite the
section; do not restate it. Your job is spotting the instance in the diff.

### Panic risk

- Nil pointer dereference on a value not nil-checked first.
- Type assertion without the `, ok` form and without a fallback, on SDK responses or
  map values.
- Slice indexing without a length check on SDK, user, or external data.
- `MustX` outside `init()` or a package-level `var` — it becomes a runtime panic at
  call time rather than a startup failure.
- Sending on a pipeline after it is closed. Closing twice is safe — `Close` is guarded
  by a `sync.Once` — so do not flag a double close.

### Dropped errors

The `%w`, `errors.Is`, and no-string-matching rules are `DEVELOPMENT.md` §3. Cite them;
do not re-derive them. What belongs here is the diff-local judgment of whether a drop
is deliberate:

- `if err != nil { return nil }` with no log at `slog.Warn` or higher and no comment
  saying why. Deliberate best-effort is fine when it is documented; silent is a defect.
- Returning `nil` on partial failure when the contract is all-or-nothing.
- Swallowing a sentinel the caller relies on — `io.EOF`, `context.Canceled`, a
  not-found error.

Enrichment is best-effort by design (`ARCHITECTURE.md` §7). An enricher error that is
logged and continued is correct, not a dropped error.

### Test meaningfulness

Only when test files are part of the PR. You may not demand more tests.

- Tautological assertions that pass without exercising the change.
- Mocks that swallow the path the test claims to exercise.
- Table-driven rows that all land on the same branch.
- Fixtures that never reach the new code.
- Assertions on internal state instead of on the contract.
- A test whose failure would not represent a regression of the changed behavior.

### Cypher

A query that drops the matched target from `WITH` and re-matches it downstream produces
O(n²) false edges. Carry the target through: `WITH attacker, target`.

## Pass 2 — architecture invariants

Check the diff against `ARCHITECTURE.md`. Name the section in the finding. Do not
restate the rule — the author reads it at the anchor.

| Concern | Anchor |
| --- | --- |
| Layering, dependency direction | §1 |
| File and directory placement | §2 |
| Module contract, registration, thin `Run()` | §3 |
| Pipeline lifecycle and what `Run` returns | §4 |
| Components and the registry pattern | §5 |
| Parameter binding, tags, post-bind | §6 |
| Enricher registration, mutator and evaluator split | §7 |
| Output types | §8 |
| Pagination, region fan-out, rate limiting, keyed state | §9 |
| The six prohibitions | §10 |
| Load-bearing patterns — a carve-out, never a finding | §11 |

§4 is the highest-value check in this pass; it is the codebase's primary deadlock
source. §10 prohibition 5 binds new and changed code only — the tree has pre-existing
violations, so do not flag untouched lines.

Go craft — stdlib over hand-rolled loops, error wrapping, concurrency primitives,
logging, generics — is `DEVELOPMENT.md` §§1-6. Same discipline: cite the section.

## Pass 3 — principles

Mandatory. This is what holds a PR author accountable to `DEVELOPMENT.md` §§7-9. Each
of those sections defines a **Rule**, an observable **Trigger**, and **Carve-outs**.

1. **Trigger required.** Fire only when the diff shows the observable trigger the
   section defines. No trigger, no finding. This is what separates enforcement from
   taste.
2. **Cite the anchor.** Name the `DEVELOPMENT.md` section. The author must be able to
   read the rule, check the carve-outs, and contest a specific claim.
3. **Carve-outs checked first,** including `ARCHITECTURE.md` §11. A carve-out hit is
   silent — not a finding with a caveat attached.

Scope discipline still applies: no demands for new tests, no naming or formatting nits,
no refactors outside the diff.

## Severity

- **high** — a behavioral defect from pass 1.
- **medium** — an architecture deviation from pass 2, or a pass 3 principle violation
  whose trigger fired.
- **low** — a soft preference. `regexp.MustCompile` in a hot path that belongs at
  package level. A non-trivial inline closure that deserves a name.

A principle finding reaches high only when the trigger also implies a defect — for
example a config field added and never read, so the setting is silently ignored at
runtime.

No per-rule severity table. Severity follows the pass that produced the finding.

## Output

One comment: a summary of what the PR actually does, drawn from the diff rather than
the PR body, then a findings table with number, severity, rule, file, location, and
detail. Optional notes last.

Caps:

- Under 15 findings.
- At least two-thirds from pass 1, unless the PR is purely a convention fix.
- Quality over quantity. If a finding would not survive a human reviewer's pushback,
  omit it.

Use `No issues found — LGTM pending human review.` only when pass 1 produced nothing
at all and passes 2 and 3 produced nothing above low severity. A low-severity finding
still goes in the table; it does not by itself withhold the line. Anything in pass 1,
or any medium or high from passes 2 or 3, means findings — not LGTM. Notes entries do
not affect this: pre-existing observations are compatible with LGTM.
