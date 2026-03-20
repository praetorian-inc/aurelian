# Development Guide

## Architecture

Aurelian has three core patterns: **Modules**, **Pipelines**, and **Components**. Modules are entry points, Pipelines are the concurrency primitive, and Components are reusable building blocks.

### Modules

A Module implements the `plugin.Module` interface and is the top-level unit of work. Modules are registered in `init()`, discovered automatically, and wired into the CLI.

```go
type Module interface {
    ID() string
    Name() string
    Description() string
    Platform() Platform                              // aws, azure, gcp
    Category() Category                              // recon, analyze, secrets
    OpsecLevel() string
    Authors() []string
    References() []string
    SupportedResourceTypes() []string                // input targets, NOT internally-discovered types
    Parameters() any                                 // pointer to config struct, or nil
    Run(cfg Config, out *pipeline.P[model.AurelianModel]) error
}
```

**Rules:**
- Live in `pkg/modules/<csp>/<category>/` (e.g., `pkg/modules/aws/recon/`)
- Register via `plugin.Register(&MyModule{})` in `init()`
- Emit results into `out` pipeline via `out.Send()` — never return results directly
- Embed a config struct with `param` tags for automatic CLI flag generation
- `Parameters()` returns a pointer to the config struct; the framework calls `Bind` automatically via `ModuleWrapper`

### Pipelines

`pipeline.P[T]` is a generic, unbuffered channel wrapper providing streaming with backpressure.

**Operations:**
- `pipeline.New[T]()` — create a pipeline
- `pipeline.From(items...)` — create a pipeline pre-loaded with items
- `pipeline.Pipe(in, fn, out)` — transform items from `in` through `fn` into `out` (runs in a goroutine)
- `out.Send(item)` — emit one item (blocks until consumed)
- `out.Collect()` — drain into a slice
- `out.Wait()` — block until closed, return error

The **pipeline function signature** is the universal contract:

```go
func(input T, out *pipeline.P[U]) error
```

Any function matching this signature can be used with `pipeline.Pipe`.

### Components

Components are reusable utility types that expose pipeline-compatible methods. There is no formal interface — "component" means any struct whose methods conform to the pipeline function signature.

**Rules:**
- Live in `pkg/<csp>/<component>/` (e.g., `pkg/aws/cloudcontrol/`, `pkg/azure/resourcegraph/`)
- Constructed via `NewXxx(opts)` factory functions
- Expose one or more methods matching `func(input T, out *pipeline.P[U]) error`
- Can be wired into any module via `pipeline.Pipe`

### Composition

A typical module orchestrates components through pipelines:

```go
func (m *MyModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
    lister := cloudcontrol.NewCloudControlLister(m.AWSCommonRecon)
    enricher := enrichment.NewAWSEnricher(m.AWSCommonRecon)
    evaluator := publicaccess.NewResourceEvaluator(m.AWSCommonRecon, m.OrgPolicies)

    types := pipeline.From(resourceTypes...)
    listed := pipeline.New[output.AWSResource]()
    pipeline.Pipe(types, lister.ListByType, listed)

    enriched := pipeline.New[output.AWSResource]()
    pipeline.Pipe(listed, enricher.Enrich, enriched)

    evaluated := pipeline.New[publicaccess.PublicAccessResult]()
    pipeline.Pipe(enriched, evaluator.Evaluate, evaluated)

    pipeline.Pipe(evaluated, toModel, out)
    return out.Wait()
}
```

The module owns the pipeline topology. Components are stateless processors. Pipelines handle concurrency and backpressure.

## Pipeline Lifecycle

Understanding when to call `out.Wait()` vs `return nil` is critical to avoid deadlocks.

`out.Wait()` is only needed when the module pipes an internal pipeline directly into `out`. When the module calls `out.Send()` directly, `return nil` is correct — the caller's `Pipe` goroutine handles `Close()` via defer.

Calling `out.Wait()` when it's not needed will **deadlock** — `Wait()` blocks on `<-out.done`, but `out.done` is only closed by `Close()`, which fires in the caller's defer *after* `Run` returns.

```go
// Direct sends — return nil
func (m *MyModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
    for _, r := range m.scan() {
        out.Send(r)
    }
    return nil  // caller's Pipe defer handles Close()
}

// Internal pipeline piped into out — return out.Wait()
func (m *MyModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
    types := pipeline.From(resourceTypes...)
    listed := pipeline.New[output.AWSResource]()
    pipeline.Pipe(types, lister.ListByType, listed)
    pipeline.Pipe(listed, toModel, out)  // inner goroutine now owns out
    return out.Wait()                     // wait for that goroutine
}

// Range loop draining internal pipeline — return internal.Wait()
func (m *MyModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
    listed := pipeline.New[output.AWSResource]()
    pipeline.Pipe(source, lister.ListByType, listed)
    for r := range listed.Range() {
        out.Send(r)
    }
    return listed.Wait()  // wait on internal pipeline, not out
}
```

| Pattern | Return | Why |
|---|---|---|
| `out.Send()` directly, no internal pipelines | `return nil` | Caller's `Pipe` defer handles `Close()` |
| Internal pipelines, manually drain to `out` | `return lastInternal.Wait()` | Internal pipelines need explicit completion |
| `pipeline.Pipe(x, fn, out)` — piping into `out` | `return out.Wait()` | Must wait for inner goroutine that now owns `out` |

## Parameters

Modules declare parameters as struct fields with `param` tags. The framework derives CLI flags, binds values, validates, and populates the struct automatically. Embed shared parameter groups (e.g., `plugin.AWSCommonRecon`) for standard fields. Use the `PostBinder` interface for complex setup like resolving `"all"` regions or loading files.

```go
type PostBinder interface {
    PostBind(cfg Config, m Module) error
}
```

## Core Utilities

### Paginator

`ratelimit.Paginator` handles paginated API calls with automatic retry and exponential backoff on throttling.

```go
paginator := ratelimit.NewPaginator()
return paginator.Paginate(func() (bool, error) {
    result, err := client.ListResources(ctx, input)
    if err != nil { return true, err }
    // process result...
    nextToken = result.NextToken
    return nextToken != nil, nil
})
```

### Region Actor

`ratelimit.CrossRegionActor` provides fan-out across regions with per-region rate limiting.

- `ActInRegions(regions, fn)` — run `fn` in every region with a global concurrency cap
- `ActInRegion(region, fn)` — acquire a per-region semaphore before running `fn`

### store.Map

`store.Map[T]` is a generic key-value map that swaps between in-memory and SQLite-backed storage at build time (`-tags cache_sqlite`).

**Use pipelines by default.** Only use `store.Map` when the workflow requires collecting all items before processing even one item in the next step (e.g., IAM relationship processing in the graph module).

```go
m := store.NewMap[MyType]()
m.Set("key", value)
v, ok := m.Get("key")
m.Range(func(key string, value MyType) bool { ... })
```

## Integration Tests

Integration tests run modules and components against live cloud infrastructure provisioned via Terraform fixtures.

### File Conventions

| Item | Pattern |
| --- | --- |
| Test file | `<module_name>_integration_test.go` in same package as module |
| Build tag | `//go:build integration` (first line, before package) |
| Terraform fixture | `test/terraform/<platform>/<category>/<module>/` |

### Test Structure

```go
//go:build integration

package recon

import (
    "context"
    "testing"

    "github.com/praetorian-inc/aurelian/pkg/model"
    "github.com/praetorian-inc/aurelian/pkg/pipeline"
    "github.com/praetorian-inc/aurelian/pkg/plugin"
    "github.com/praetorian-inc/aurelian/test/testutil"
    "github.com/stretchr/testify/require"
)

func TestMyModule(t *testing.T) {
    fixture := testutil.NewAWSFixture(t, "aws/recon/my-module")
    fixture.Setup()

    mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "my-module")
    if !ok {
        t.Fatal("module not registered")
    }

    cfg := plugin.Config{
        Args:    map[string]any{"regions": []string{"us-east-2"}},
        Context: context.Background(),
    }
    p1 := pipeline.From(cfg)
    p2 := pipeline.New[model.AurelianModel]()
    pipeline.Pipe(p1, mod.Run, p2)

    results, err := p2.Collect()
    require.NoError(t, err)
    testutil.AssertMinResults(t, results, 1)

    t.Run("discovers expected resource", func(t *testing.T) {
        testutil.AssertResultContainsString(t, results, fixture.Output("resource_id"))
    })
}
```

### Terraform Fixtures

Each fixture is a standard Terraform module with S3 backend.

**Mandatory:** Integration fixtures must declare `backend "s3" {}`. Fixture setup passes `-backend-config` values that require the S3 backend type.

```hcl
terraform {
  backend "s3" {}
}

output "resource_ids" {
  value = [aws_instance.test.id]
}
```

- Use a `prefix` variable/local for unique naming (avoids collisions)
- Export all identifiers tests need as outputs (ARNs, IDs, names)
- Fixture dir mirrors module path: `aws/recon/graph.go` → `test/terraform/aws/recon/graph/`

### Subtests

Run the module once, then use `t.Run()` for per-resource assertions. This gives clear failure diagnostics without re-running the module.

### Component Integration Tests

Components reuse an existing module's Terraform fixture. Instantiate the component directly instead of looking up via `plugin.Get`.

### Ephemeral Fixture Data

Some fixture resources contain data that expires (e.g., CloudWatch log events). Use `testutil` helpers to re-inject ephemeral data between `fixture.Setup()` and module execution.

```go
fixture.Setup()
testutil.EnsureLogEvent(t, "us-east-2",
    fixture.Output("log_group_name"),
    fixture.Output("log_stream_name"),
    fixture.Output("log_event_message"),
)
```

### Graph Analysis Tests (Neo4j)

Graph analysis modules require a Neo4j container. Use a shared container via `TestMain`:

```go
var sharedNeo4jBoltURL string

func TestMain(m *testing.M) {
    ctx := context.Background()
    boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
    if err != nil {
        os.Exit(1)
    }
    sharedNeo4jBoltURL = boltURL
    code := m.Run()
    cleanup()
    os.Exit(code)
}
```

- One Neo4j container per package via `TestMain` — never per-test (10x slower)
- Call `testutil.ClearNeo4jDatabase()` before each test to reset graph state
- Docker required for graph tests
- Use `-timeout 30m` — IAM provisioning can take 15–30 min

### Test Coverage Expectations

| Module type | Minimum assertions |
| --- | --- |
| Resource enumeration | 5+ distinct resource checks |
| Risk/finding detection | 3–5+ unique risk outputs |
| Public resource detection | 3–5+ resource + field checks |

For risk-producing modules, assert on fields not just existence: risk name, severity, context, and impacted resource identifiers.

## Review Checklist

When reviewing module code, check for:

- [ ] `out.Wait()` / `return nil` used correctly per pipeline lifecycle rules
- [ ] Pipeline functions extracted to named methods (no inline closures in `pipeline.Pipe`)
- [ ] Component methods conform to `func(input T, out *pipeline.P[U]) error`
- [ ] No interfaces created solely for unit test mocking
- [ ] `SupportedResourceTypes()` lists input targets, not internally-discovered types
- [ ] AWS SDK v2 only (no `github.com/aws/aws-sdk-go` v1 imports)
- [ ] `ratelimit.NewCrossRegionActor()` used instead of `ratelimit.Global()`
- [ ] Modern Go idioms (`slices`, `maps`, `cmp`, `errors.Is`/`%w`, `strings.Cut`)
- [ ] No speculative abstractions or unused configurability (YAGNI)
- [ ] No duplicated logic across modules (DRY)
- [ ] Comments explain *why*, not *what*
