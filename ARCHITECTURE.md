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
