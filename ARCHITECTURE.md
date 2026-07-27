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
| `pkg/modules/aws/rules/` | Declarative YAML rules consumed by `pkg/modules/common/`. | Data, not code. |
| `pkg/modules/common/` | CSP-agnostic YAML rule engine: analyzer, matcher, rule. | Not a CSP. Nothing CSP-specific goes here. |
| `pkg/modules/loader/` | Generated blank-import file. | `pkg/modules/loader/loader.go` is generated — `go generate ./pkg/modules/loader`. Never hand-edit. |
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
  `OpsecLevel`, `Authors`, `References`) return fixed values. No I/O, no config reads.
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

Every registry in `pkg/plugin` has the same shape: a package-level map guarded by a
mutex, a `Register*` function called from `init()`, and a `Get*` lookup at dispatch
time. Enrichers get one registry per CSP, not one shared map.

| Registry | Register | Keyed on |
| --- | --- | --- |
| Modules | `plugin.Register` | `platform/category/id` |
| Enrichers (one per CSP) | `plugin.RegisterEnricher`, `plugin.RegisterAzureEnricher`, `plugin.RegisterGCPEnricher` | resource type |
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

## 8. Output types

`pkg/output` holds every result type. Emitted types satisfy `model.AurelianModel` by
embedding `model.BaseAurelianModel` — `output.AWSIAMResource` gets it transitively
through the `output.AWSResource` it embeds. This is the complete set:

| Type | Source | Use |
| --- | --- | --- |
| `output.AWSResource` | `aws_resource.go:19` | An AWS resource and its properties |
| `output.AzureResource` | `azure_resource.go:6` | An Azure resource |
| `output.GCPResource` | `gcp_resource.go:6` | A GCP resource |
| `output.AWSIAMResource` | `aws_iam_resource.go:8` | IAM principals and policies |
| `output.AWSIAMRelationship` | `aws_iam_relationship.go:7` | Edges between IAM principals |
| `output.AurelianRisk` | `aurelian_risk.go:36` | A security finding |
| `output.Risk` | `risk.go:8` | Legacy finding shape — see below |
| `output.AnalyzeResult` | `analyze_result.go:13` | Analysis module results |
| `output.CallerIdentity` | `aws_caller_identity.go:7` | Resolved AWS caller |
| `output.AWSCostSummary` | `aws_cost_summary.go:10` | Cost Explorer summary |
| `output.AzureConditionalAccessPolicy` | `azure_conditional_access.go:6` | Entra CA policy, with `output.ResolvedEntity` and the `ConditionalAccess*` sub-shapes |
| `output.ScanInput` | `scan_input.go:4` | Content extracted for secret scanning. The one exception: it does not embed `model.BaseAurelianModel` and is not emitted — it is an intermediate carried between `pkg/<csp>/extraction/` and the scanner. |

There is no `CloudResource` type and no `SecretFinding` type; anything citing either
is wrong. Secret scanning results are `secrets.SecretScanResult`
(`pkg/secrets/scanner.go:24`).

### Risk versus AurelianRisk

Both exist. They are not interchangeable.

`output.AurelianRisk` is the current shape and the one modules emit: 15 composite
literals across 9 files under `pkg/modules/`, referenced by 28 files. It carries a
`RiskSeverity` (`output.NormalizeSeverity` canonicalizes the string) and a
`json.RawMessage` context blob.

`output.Risk` has zero composite literals under `pkg/modules/`. It is constructed only
by the CDK scanner in `pkg/aws/cdk` (10 literals) and forwarded unchanged by one
module, `pkg/modules/aws/recon/cdk_bucket_takeover.go:64`. It carries a `Target
*AWSResource` and a two-letter `Status` severity code.

New findings use `output.AurelianRisk`. `output.Risk` stays confined to the CDK path.

### Direction

Output types are migrating to capability-sdk/pkg/capmodel. Not yet landed in Aurelian:
go.mod has no capability-sdk requirement and the tree has no capmodel references.

Plan: docs/superpowers/plans/2026-04-29-aurelian-capability-sdk-migration.md
Aurelian's work is phases 4-6, gated behind phases 1-3 in capability-sdk, tabularium,
and guard. Translation will live in pkg/sdkadapter/, not in modules. capmodel has
per-CSP resource models and its own risk and proof models.

When phase 4 lands and pkg/sdkadapter/ exists, this section flips: capmodel becomes
current, pkg/output becomes legacy, and the section 10 import boundary narrows to
modules only. This doc is staged for that, not stale.

## 9. Cross-cutting infrastructure

Use these rather than hand-rolling. Each already handles a failure mode that bit this
codebase.

**Pagination and retry.** `pkg/ratelimit` supplies one paginator per CSP, differing
only in the retry predicate: `ratelimit.NewAWSPaginator` (`paginator.go:20`, retries
`ThrottlingException: Rate exceeded`), `ratelimit.NewGCPPaginator` (`:30`, retries 429
and 503), `ratelimit.NewAzurePaginator` (`:43`, retries 429 and 503 via
`azcore.ResponseError`). Default `MaxAttempts` is 5.

**Region fan-out.** `ratelimit.NewCrossRegionActor(concurrency)`
(`region_actor.go:19`). `ActInRegions` bounds workers with `errgroup` `SetLimit` and
acquires the per-region limiter for each call; `ActInRegion` does one region. Do not
write manual region loops — they bypass the per-region limiter and throttle the account.

**Rate limiting.** `ratelimit.NewAWSRegionLimiter(limit)` (`aws_region_limiter.go:48`)
gives each region its own semaphore. `ratelimit.Global()` (`:57`) also exists: a
process-wide singleton fixed at 5 per region, shared by every concurrent scan. It has
no callers today and new code does not add one — see section 10.

**Keyed state.** `store.Map[T]` (`pkg/store/map.go:43`). `store.NewMap[T]()` (`:48`)
returns a **value**, not a pointer; a zero-value `Map` is safe to use, so call sites
need no nil checks. Build tags select the backend: `compute` uses SQLite
(`pkg/store/new_map_sqlite.go`), `!compute` uses memory (`pkg/store/new_map.go`).
Reach for it only when a later stage needs random-access lookup of earlier results. A
pipeline is almost always the better answer.

## 10. Boundaries

Six prohibitions. Prohibitions 1, 2, 3, 4, and 6 have zero violations today, so any
hit is a regression. Prohibition 5 has pre-existing violations; it binds new and
changed code.

1. **AWS SDK v2 only.** `github.com/aws/aws-sdk-go` (v1) is prohibited. go.mod
   requires only `aws-sdk-go-v2` modules and the tree has zero v1 imports.
2. **No Chariot or Tabularium imports under `pkg/modules/`.** Zero today. Aurelian
   ships as a standalone binary and module code stays free of platform coupling.
3. **No dispatcher or orchestrator package.** Neither pkg/dispatcher nor
   pkg/orchestrator exists and neither may be created. Dispatch is the registry
   (section 5); modules go in `pkg/modules/`.
4. **No `ratelimit.Global()` in new code.** It is a process-wide singleton pinned at 5
   concurrent calls per region, shared across unrelated scans, with no way to tune it
   per module. Construct a scoped `ratelimit.NewAWSRegionLimiter(limit)` or use
   `ratelimit.NewCrossRegionActor`. Current callers: zero. Keep it that way.
5. **Parse resource identifiers with a real parser, never `strings.Split`.** AWS:
   `arn.Parse` from the SDK. Azure: `arm.ParseResourceID`. GCP publishes no equivalent
   — use the shared helpers in `pkg/gcp/enumeration/resource_helpers.go` rather than
   splitting a self-link inline.
6. **No `capability-sdk` import under `pkg/modules/`.** Modules emit
   `model.AurelianModel`; translation to capmodel belongs in a future
   pkg/sdkadapter/. From the migration plan's constraint table: *"No capability-sdk
   imports leak into Aurelian module `init()`. SDK registration lives in chariot
   bridge."* This is enforceable now, before any of the migration lands, and it is what
   protects the standalone-binary constraint. Section 8 Direction describes the
   migration; this is the rule.

## 11. Load-bearing patterns

These four look like dead code, over-engineering, or indirection for its own sake.
They are none of those. Do not flag them, and do not "simplify" them away.

1. **Blank imports for `init()` side effects.** `_ "path"` in `cmd/module_imports.go`
   and `pkg/modules/loader/loader.go` is the only thing that makes a module reachable.
   An unused-looking import here is the wiring.
2. **`init()` functions and registry self-registration.** `plugin.Register`,
   `plugin.RegisterEnricher` and peers, `plugin.RegisterAzureEvaluator`. The registered
   function has no static caller by design; the registry is the caller.
3. **Dispatch through a registry or reflection.** Enricher and evaluator functions are
   invoked from a map keyed by resource type or template ID. `plugin.PostBinder` is
   discovered by reflection over embedded structs (`pkg/plugin/module.go:136`). Neither
   has a call site a static analyzer can see.
4. **Interface boundaries for CSP polymorphism.** An interface with one implementation
   today is correct when it exists to hold the AWS/Azure/GCP/Kubernetes shape uniform.
   The second implementation is the point.
