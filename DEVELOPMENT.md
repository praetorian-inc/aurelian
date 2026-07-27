# Development Standards

Normative Go craft rules for this repository. Code review enforces all of them.
Architecture-specific contracts live in ARCHITECTURE.md.

## 1. Go version

`go.mod` declares Go 1.25.8. Every pattern in this document is available at that
version, so "the compiler doesn't support it" is never true here.

The declared version is the only valid reason to reject a modern pattern. Team
familiarity, time pressure, and "the surrounding code does it the old way" are not.

When you touch a file, modernize the legacy patterns in the code you touch. Do not
sweep files the task does not touch (§8).

## 2. Legacy smells

If the stdlib has a function for it, use the stdlib function. A manual loop that
`slices`, `maps`, or `cmp` already implements is legacy code.

| Legacy | Modern |
| --- | --- |
| Loop to find an element | `slices.Contains`, `slices.ContainsFunc` |
| Loop returning an index | `slices.Index` |
| `sort.Slice`, `sort.Strings` | `slices.Sort`, `slices.SortFunc` |
| `append([]T(nil), s...)`, make + copy loop | `slices.Clone`, `maps.Clone` |
| `append(s[:i], s[j:]...)` | `slices.Delete` |
| Manual consecutive-dedup loop | `slices.Compact` |
| Length check + element-compare loop | `slices.Equal`, `maps.Equal` |
| make + append + append | `slices.Concat` |
| Loop copying map entries | `maps.Copy` |
| Custom `minInt` / `maxInt` helpers | `min`, `max` builtins |
| `for k := range m { delete(m, k) }` | `clear(m)` |
| Conditional map-delete loop | `maps.DeleteFunc` |
| `for i := 0; i < n; i++` | `for i := range n` |
| Chained `if x == "" { x = fallback }` | `cmp.Or(x, fallback)` |
| Loop to collect and sort map keys | `slices.Sorted(maps.Keys(m))` |
| Loop to collect map values | `slices.Collect(maps.Values(m))` |
| Index arithmetic to batch a slice | `slices.Chunk(s, size)` |
| Channel-based iterator | `iter.Seq`, `iter.Seq2` |
| `strings.SplitN(s, sep, 2)` | `strings.Cut` |
| `HasPrefix` + `TrimPrefix` | `strings.CutPrefix` (same for `CutSuffix`) |
| `interface{}` | `any` |
| `err == ErrSentinel` | `errors.Is` (§3) |
| `log.Printf` with a formatted string | `slog` (§5) |
| `sync.WaitGroup` + error channel | `errgroup` (§4) |
| Manual `b.N` loop in a benchmark | `for b.Loop()` |

Loop variable copies (`v := v` at the top of a loop body) are dead code. Delete on
sight.

Multi-field sort composes through `cmp.Or`:

```go
slices.SortFunc(rows, func(a, b Row) int {
    return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
})
```

Two traps:

- `clear(s)` on a slice zeros the elements and keeps `len(s)`. Use `s = s[:0]` to
  truncate.
- `cmp.Or` evaluates every argument eagerly. Never pass it an expensive call.

## 3. Error handling

- Wrap with `%w`, not `%v`. `%w` preserves the chain that `errors.Is` and `errors.As`
  walk.
- Use `%v` only to deliberately hide an internal error from callers. That is an API
  decision — make it on purpose, not by reflex.
- Compare with `errors.Is`, never `==`. Equality breaks the moment anything in the
  call path wraps.
- Reach a concrete error type with `errors.As`, never a type assertion.
- Aggregate with `errors.Join(errs...)`. It returns nil when every element is nil. No
  third-party multierror package.
- `fmt.Errorf` accepts more than one `%w` in a single format string.
- **Never classify an error by string-matching its message.** Provider and SDK message
  text changes without notice and silently disables the branch. Use `errors.As` to get
  the typed error and read its code — cloud SDK error types expose an `ErrorCode()`
  accessor for exactly this.
- Every wrap must add context the caller does not already have. `"failed to fetch: %w"`
  inside `Fetch` adds nothing; the location is already in the chain.
- Handle the error or return it. Never both, and never discard it into `_`.

## 4. Concurrency

Use `errgroup` (`golang.org/x/sync/errgroup`) whenever concurrent work can fail. It
replaces `sync.WaitGroup` plus an error channel plus manual cancellation.

```go
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(10) // match the real constraint: pool size, rate limit, CPU count
for _, item := range items {
    g.Go(func() error { return process(ctx, item) })
}
if err := g.Wait(); err != nil {
    return fmt.Errorf("processing items: %w", err)
}
```

- `WithContext` cancels the derived context on the first error. Use it; do not
  hand-roll cancellation.
- `SetLimit` replaces semaphore channels. `g.Go` blocks once the limit is reached, so
  no buffered channel is needed.
- Use `TryGo` when the correct behavior is to skip work rather than wait for a slot.
- Long-running goroutines must check `ctx.Err()` or select on `ctx.Done()`. A goroutine
  that ignores cancellation is a leak.
- Never reuse a Group after `Wait`. Construct a new one.
- `ctx context.Context` is the first parameter of any function that blocks, and it is
  propagated, not replaced with `context.Background()` mid-call.
- Do not store a request-scoped context in a struct that outlives the request.
- `context.WithoutCancel` for work that must outlive its parent.
- `context.AfterFunc` for cleanup on cancellation, instead of a goroutine parked on
  `<-ctx.Done()`.
- Guard shared mutable state with a mutex or keep it in one goroutine. Run the race
  detector on anything concurrent: `go test -race ./...`.

## 5. Structured logging

`slog` only. Key-value attributes, never a preformatted message.

```go
slog.Info("scan complete", "target", target, "findings", len(findings))
```

- Severity: `Debug` is developer trace detail. `Info` is normal operation, one record
  per meaningful unit of work. `Warn` is degraded but proceeding. `Error` is the
  operation failed.
- Do not log an error and also return it — the caller logs it again, and one failure
  becomes five records. Whoever stops propagating it logs it.
- Scope repeated attributes instead of retyping them:
  `logger := slog.Default().With("run_id", runID)`. Pass the logger down.
- Attribute keys are stable snake_case identifiers. Never interpolate a value into a
  key; that makes the field unqueryable.
- Never log credentials, tokens, or raw customer data. Log identifiers.

## 6. Generics

Three valid uses, and no others:

1. Container utilities over slices, maps, or channels where the element type varies.
2. Generic data structures — sets, trees, queues.
3. Identical implementations where only the type differs.

- Write the concrete code first. Add type parameters when duplication exists, not when
  you predict it (§8).
- Do not replace an interface with a type parameter. If the body only calls methods,
  take the interface.
- Use the minimum sufficient constraint: `any` < `comparable` < `cmp.Ordered` < a
  custom method interface. Over-constraining rejects valid callers.
- Do not under-constrain either. A constraint too loose for the body forces type
  assertions back inside, which defeats the point.
- Let inference work. Do not spell out type arguments the compiler deduces.
- Prefer a function parameter such as `cmp func(T, T) int` over a method constraint.
  Method constraints force wrapper types around primitives.
- Iterators are `iter.Seq[V]` and `iter.Seq2[K, V]`. Always honor a false return from
  `yield` and stop. Never use a channel as an iterator.

## 7. DRY

**Rule.** Extract logic that appears three times into a shared component or helper.

**Trigger.** The same logic appears a third time. Two occurrences is not a violation —
two is the sample size at which the wrong abstraction still looks correct. Naming
tells: numbered identifiers (`data1`, `data2`), parallel function families, adjacent
blocks differing only in a constant.

**Carve-outs.** Parallel implementations of one interface that merely resemble each
other and will diverge on their own schedule. Generated code. Test fixtures and test
setup, where readability beats deduplication. Patterns not yet clear enough to name.
See ARCHITECTURE.md §11.

## 8. YAGNI

**Rule.** Build only what the current change requires.

**Trigger.** A parameter, struct field, config value, or exported helper added in this
diff with zero readers in this diff. An interface with one implementation and no second
one named in the PR. A config struct where a literal or an existing flag would do. A
dependency for something the stdlib already does. Compile-time interface-compliance
assertions, and placeholder types with no members.

**Carve-outs.** ARCHITECTURE.md §11 load-bearing patterns. Correctness work the
requested change depends on: a bug that would break it, a security hole it would
introduce, a data-loss path it would open. Take those, and say so in the PR
description.

## 9. Comments

**Rule.** Comment why, never what.

**Trigger.** A comment restating what the next line does. Doc comments of the form
`// NewFoo creates a new Foo` on a self-describing signature.

**Carve-outs.** Non-obvious behavior, and the reason for it. External constraints the
code cannot express (rate limits, provider quirks, protocol requirements). Algorithms
whose correctness argument is not visible locally. Deliberate-simplification markers
recording that the simple form was chosen on purpose.
