# Aurelian

Cloud security reconnaissance framework. Detects and validates cloud weaknesses at scale across AWS, Azure, and GCP.

## Quick Reference

- **Language:** Go 1.25+ (use modern idioms: `slices`, `maps`, `cmp`, `min`/`max` builtins, `range n`, `errors.Is`/`%w`, `strings.Cut`)
- **Module path:** `github.com/praetorian-inc/aurelian`
- **Architecture details:** See [DEVELOPMENT.md](DEVELOPMENT.md)

## Commands

```bash
# Build
go build -o aurelian .

# Build with SQLite-backed store (for memory-constrained environments)
go build -tags cache_sqlite -o aurelian .

# Unit tests
go test ./...

# Integration tests (requires cloud credentials + terraform)
go test -tags=integration -v -timeout 30m ./pkg/modules/aws/recon/
go test -tags=integration -v -timeout 30m ./pkg/modules/azure/recon/

# Graph/analyze tests (requires Docker for Neo4j)
go test -tags=integration -v -timeout 30m ./pkg/modules/aws/analyze/

# Vet
go vet ./...
```

## Project Layout

```
pkg/
  modules/<csp>/<category>/   # Modules (entry points) — aws/recon/, azure/recon/, etc.
  <csp>/<component>/          # Components (reusable building blocks) — aws/cloudcontrol/, azure/resourcegraph/, etc.
  pipeline/                   # Pipeline concurrency primitive
  plugin/                     # Module interface, registry, parameter binding
  model/                      # AurelianModel output type
  store/                      # Generic key-value map (in-memory or SQLite)
  ratelimit/                  # Paginator, CrossRegionActor
test/
  terraform/<csp>/<category>/<module>/  # Terraform fixtures for integration tests
  testutil/                             # Test helpers (fixtures, assertions, Neo4j)
```

## Code Principles

- **DRY:** Extract shared logic into components. Reuse existing components from `pkg/` before creating new ones.
- **YAGNI:** Only build what the current task requires. No speculative abstractions.
- **Minimal comments:** Only comment *why*, never *what*. No doc comments on unexported types unless behavior is surprising.

## Key Rules

- Modules emit results via `out.Send()` into `*pipeline.P[model.AurelianModel]` — never return results directly
- Register modules via `plugin.Register(&MyModule{})` in `init()`
- Use `pipeline.Pipe` with named methods — no inline closures
- Component methods must conform to `func(input T, out *pipeline.P[U]) error`
- Use AWS SDK v2 only — v1 is deprecated
- Use `ratelimit.NewCrossRegionActor()` — not `ratelimit.Global()`
- Use integration tests for cloud SDK interactions — no mock-only interfaces
- `SupportedResourceTypes()` declares input targets, not internally-discovered types

## Pipeline Lifecycle (Deadlock Prevention)

| Pattern | Return | Why |
|---|---|---|
| `out.Send()` directly | `return nil` | Caller's `Pipe` defer handles `Close()` |
| `pipeline.Pipe(x, fn, out)` — piping into `out` | `return out.Wait()` | Must wait for inner goroutine that owns `out` |
| Range loop draining internal pipeline to `out` | `return internal.Wait()` | Wait on internal pipeline, not `out` |

## Integration Tests

- Build tag: `//go:build integration` (first line, before `package`)
- Terraform fixtures use `backend "s3" {}` — never local backend
- Test file: `<module>_integration_test.go` in same package
- Fixture dir mirrors module path: `aws/recon/graph.go` → `test/terraform/aws/recon/graph/`
- Run module once, use `t.Run()` subtests for per-resource assertions
- Use `testutil.AssertMinResults`, `AssertResultContainsARN`, `AssertResultContainsString`
- Graph tests share one Neo4j container per package via `TestMain`
