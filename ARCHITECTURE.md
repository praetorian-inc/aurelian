# Aurelian Architecture

Normative. States what Aurelian is and what it must be. Rules here are binding on
new code and enforced in review.

Go language craft and code principles live in DEVELOPMENT.md, not here.
Task workflows live in .agents/skills/, not here.
Nothing in this file is restated in a skill.

Aurelian is a standalone Go binary: a modular multi-cloud security recon framework
covering AWS, Azure, GCP, and Kubernetes.

## 1. Layering

Seven layers. Each depends only on those below it.

1. **CLI** — `cmd/`. Cobra. `Execute` calls `initCommands`, which calls
   `generateCommands` (`cmd/generator.go`). One cobra command per registered module,
   one flag per parameter derived through `plugin.ParametersFrom`. No module logic
   lives here.
2. **Registry** — `pkg/plugin`. Modules self-register in `init()` via
   `plugin.Register`. `cmd/module_imports.go` and `pkg/modules/loader/loader.go`
   blank-import the module packages so those `init()` functions run. A module with no
   blank import does not exist at runtime.
3. **Modules** — `pkg/modules/<csp>/<category>/`. Thin. Bind parameters, build the
   pipeline topology, delegate to components, emit.
4. **Pipelines** — `pkg/pipeline`. `pipeline.P[T]` carries items between stages.
   Leaf package: imports nothing first-party.
5. **Components** — `pkg/<csp>/<service>/`. All cloud API calls, pagination, and
   parsing. Reused across modules.
6. **Enrichment** — enrichers and evaluators registered in `init()`, applied by
   `pkg/<csp>/enrichment/` as a pipeline stage.
7. **Output** — `pkg/output`. Result types. Serialized by `cmd/generator.go`.

Dependency direction is one-way: `cmd/` → `pkg/plugin` → `pkg/modules/` →
`pkg/<csp>/<service>/` → `pkg/output` → `pkg/model`. Components must not import
`pkg/modules/`. Nothing under `pkg/` may import `cmd/`.

## 2. Directory contract

| Directory | Contents | Rule |
| --- | --- | --- |
| `pkg/modules/<csp>/<category>/` | Module implementations. `<csp>` ∈ aws, azure, gcp. `<category>` ∈ recon, analyze, enrichers, evaluators. | One module per file. Register in `init()`. No cloud API calls — delegate to a component. |
| `pkg/modules/common/` | CSP-agnostic YAML rule engine: analyzer, matcher, rule. | Not a CSP. Nothing CSP-specific goes here. |
| `pkg/modules/loader/` | Generated blank-import file. | `pkg/modules/loader/loader.go` is generated — `go generate ./pkg/modules/loader`. Never hand-edit. |
| `pkg/modules/aws/rules/` | Declarative YAML rules consumed by `pkg/modules/common/`. | Data, not code. |
| `pkg/<csp>/<service>/` | Components: enumerators, checkers, listers, extractors, enrichment appliers. | Cloud API work lives here and only here. Must not import `pkg/modules/`. |
| `pkg/types/` | Shared structural types (IAM policy, GAAD, enriched resource description). | Cross-package types only. Not module-local shapes. |
| `pkg/graph/` | Neo4j adapters, queries, transformers. | Graph concerns only. |
| `test/terraform/<csp>/<category>/<module>/` | Terraform fixtures for integration tests. | Path mirrors the module path. One directory per module under test. |

`pkg/model`, `pkg/pipeline`, `pkg/plugin`, `pkg/output`, `pkg/ratelimit`, `pkg/store`
are framework packages, contracted in sections 3 through 9.

## 3. Module contract

A module implements `plugin.Module` (`pkg/plugin/module.go:78`) and registers itself
in `init()` with `plugin.Register` (`pkg/plugin/registry.go:30`). Registration keys on
`platform/category/id`; a duplicate key panics at startup.

- **Metadata** methods (`ID`, `Name`, `Description`, `Platform`, `Category`,
  `OpsecLevel`, `Authors`, `References`) are constant expressions. No I/O.
- **`SupportedResourceTypes()`** returns the module's *input targets* — the resource
  types a caller may aim it at. Never the types it discovers internally. Guard matches
  on this value to decide dispatch, so widening it changes orchestration.
- **`Parameters()`** returns a pointer to the module's config struct, or nil. The
  registry wraps every module in `plugin.ModuleWrapper` (`pkg/plugin/module.go:109`),
  which calls `plugin.Bind` and then the post-binders before `Run`. A module must not
  call `Bind` itself.
- **`Run()`** stays thin: read the bound config, build the pipeline topology, delegate
  to `pkg/<csp>/<service>/` components, emit. Cloud API calls in `Run` are a layering
  violation.

Modules emit `model.AurelianModel` (`pkg/model/model.go:13`). The interface is sealed
by an unexported token; the only way to satisfy it is to embed
`model.BaseAurelianModel`.

The caller owns the output pipeline, including `Close`. `cmd/generator.go:287` runs
`Run` as a `pipeline.Pipe` stage, so `Pipe` closes the pipeline once `Run` returns. A
module must never close the pipeline it was handed.

## 4. Pipeline lifecycle

`pipeline.P[T]` (`pkg/pipeline/pipeline.go:18`) wraps an unbuffered channel. Unbuffered
means every `Send` blocks until a consumer reads — backpressure is the default and
stalls are real.

Surface (`pkg/pipeline/pipeline.go`):

```
Send(item T)            Sent() int64      Close()
CloseWithError(error)   Wait() error      Range() <-chan T
Drain() error           Collect() ([]T, error)
```

`Send` returns nothing. There is no error to check.

### What Run returns

Because the caller closes the output pipeline only *after* `Run` returns, what `Run`
returns decides whether in-flight producers are still writing when that close happens.
Choose from the table. A wrong choice deadlocks or truncates output.

| Situation | Return |
| --- | --- |
| Direct `out.Send()`, no internal pipeline | `return nil` |
| `pipeline.Pipe(x, fn, out)` targets `out` | `return out.Wait()` |
| Internal pipeline drained via `Range()`, re-emitted | `return internal.Wait()` |

Row 2: the inner `Pipe` owns `out` and closes it, so `out.Wait()` blocks until that
stage finishes. Returning `nil` instead races the outer close against a live producer.

Row 3: `out` is written synchronously by `Run`'s own goroutine, so `nil` would be safe
for ordering — but returning `internal.Wait()` is what propagates the internal stage's
error. Both `Range()` and `Collect()` must be followed by a `Wait()` whose error is
returned; ranging alone silently discards upstream failures.

Never `return out.Wait()` when nothing else closes `out`. `Wait` blocks on a channel
the caller closes only after `Run` returns — that is the deadlock.

### Stage options

`pipeline.PipeOpts` (`pkg/pipeline/pipeline.go:112`) carries `Concurrency` and
`Progress`. `Concurrency > 1` selects `pipeParallel`, which bounds workers with
`errgroup` `SetLimit` (`:221`); otherwise stages run sequentially. Concurrency comes
from a bound parameter, never a literal — see section 6.

## 5. Components and the registry pattern

### Components

Components live in `pkg/<csp>/<service>/` and hold every cloud API call. They are
plain structs built by a `NewXxx()` constructor that takes the module's bound config
(`plugin.AWSCommonRecon` and peers) plus collaborators.

Their work methods are shaped `func(T, *pipeline.P[U]) error` so they drop directly
into `pipeline.Pipe` as a stage with no adapter — for example
`(*CloudControlEnumerator).List` (`pkg/aws/enumeration/cloud_control_enumerator.go:41`)
and `(*AWSEnricher).Enrich` (`pkg/aws/enrichment/enricher.go:28`). Write new component
methods to that shape.

Components have no registry and no `init()`. They are constructed explicitly by the
module that needs them, which is what makes them reusable across modules.

### The registry pattern

Three registries exist, all with the same shape: a package-level map guarded by a
mutex, a `Register*` function called from `init()`, and a `Get*` lookup at dispatch
time.

| Registry | Register | Keyed on |
| --- | --- | --- |
| Modules | `plugin.Register` | `platform/category/id` |
| Enrichers | `plugin.RegisterEnricher` and per-CSP peers | resource type |
| Azure evaluators | `plugin.RegisterAzureEvaluator` | template ID |

Registration is a side effect of importing the package. Blank imports in
`cmd/module_imports.go` and `pkg/modules/loader/loader.go` are the only thing that
makes registered code reachable. See section 11 — they are not dead code.

## 6. Parameters

Every module parameter is a tagged struct field. `plugin.Bind` (`pkg/plugin/bind.go:11`)
derives `plugin.Parameter` values from the tags via `plugin.ParametersFrom`, applies
`cfg.Args`, validates, and populates the struct. `ModuleWrapper` does this before
`Run`; modules never call it.

Supported tags: `param`, `desc`, `default`, `enum`, `shortcode`, `required`, `hidden`,
`sensitive`. Every exported, non-embedded field must carry a `param` tag — use
`param:"-"` to opt a field out. An untagged exported field fails binding at runtime
with:

```
field %q in %s is exported but has no `param` tag (use `param:"-"` to skip)
```

Embed the CSP common struct rather than redeclaring its fields:
`plugin.AWSReconBase`, `plugin.AWSCommonRecon`, `plugin.OrgPoliciesParam`,
`plugin.AzureReconBase`, `plugin.AzureCommonRecon`, `plugin.AzureEntraRecon`,
`plugin.GCPCommonRecon`.

Post-bind work — credential construction, region resolution, clamping, cross-field
validation — goes in a `PostBind` method satisfying `plugin.PostBinder`
(`pkg/plugin/module.go:105`). `runPostBindersValue` (`:136`) walks the config struct
recursively and calls `PostBind` on every embedded struct that implements it, innermost
first, so embedding `AWSCommonRecon` inherits its region resolution for free. A module
may add its own `PostBind` alongside.

Concurrency limits, thresholds, and timeouts are parameters, never magic constants.

## 7. Enrichers

An enricher adds properties a bulk listing cannot return. Registration happens in
`init()`; the function is keyed by resource type.

| CSP | Register | Operates on | Source |
| --- | --- | --- | --- |
| AWS | `plugin.RegisterEnricher` | `output.AWSResource` | `pkg/plugin/enricher.go:27` |
| Azure | `plugin.RegisterAzureEnricher` | `templates.ARGQueryResult` | `pkg/plugin/azure_enricher.go:34` |
| GCP | `plugin.RegisterGCPEnricher` | `output.GCPResource` | `pkg/plugin/gcp_enricher.go:27` |

Azure enrichers operate on Resource Graph query results, not on `output.AzureResource`.

Enricher implementations live in `pkg/modules/<csp>/enrichers/`. They are applied as a
pipeline stage by `pkg/<csp>/enrichment/`.

### Mutators versus evaluators

Split the two. A **mutator** is an enricher: it fills in fields on the resource and
returns. An **evaluator** decides whether a condition holds. Azure evaluators are a
separate registry — `plugin.RegisterAzureEvaluator` (`pkg/plugin/azure_evaluator.go:23`),
keyed by template ID, returning `bool`, implemented in
`pkg/modules/azure/evaluators/`. Risk emission belongs to the module or an evaluator
stage, not inside a mutating enricher.

### Enrichment is best-effort

An enricher returning an error does not fail the pipeline. The applier logs
`slog.Warn` and forwards the resource unchanged (`pkg/aws/enrichment/enricher.go:52`).
A failure to build the per-region cloud config is likewise logged and skipped. Write
enrichers so a partial result is still useful, and never rely on an enricher's error
to abort a scan.
