---
name: aurelian-module-development
description: Use when adding or changing an Aurelian module, component, or enricher. Covers file placement, registration, pipeline wiring, and local verification for Go cloud recon modules across AWS, Azure, and GCP.
license: Apache-2.0
---

# Aurelian module development

Conform to `../../../ARCHITECTURE.md` and `../../../DEVELOPMENT.md`. Deviations are
flagged in review.

This file is workflow only: what to create, in what order, and how to prove it works.
Every contract it refers to is defined once in ARCHITECTURE.md and is not restated here.
When a step cites a section, read it before writing the code.

## 0. Pick the category first

The category decides the directory, and the directory decides what you implement.

| You are adding | Goes in | Follow |
| --- | --- | --- |
| A unit of work a user invokes from the CLI | `pkg/modules/<csp>/<category>/` | Section 1 |
| Cloud API calls, pagination, parsing | `pkg/<csp>/<service>/` | Section 2 |
| Extra properties on an already-enumerated resource | `pkg/modules/<csp>/enrichers/` | Section 3 |
| A detection expressible as data, no Go | `pkg/modules/aws/rules/` | ARCHITECTURE.md §2 |

`<category>` is one of recon, analyze, enrichers, evaluators. If the detection can be a
YAML rule consumed by `pkg/modules/common/`, write the rule, not a module.

## 1. Add a module

Ordered. Do not skip step 6.

1. **Create the file.** One module per file, at
   `pkg/modules/<csp>/<category>/<name>.go`. No cloud API calls in this file — that is
   a layering violation (ARCHITECTURE.md §1).

2. **Define the config struct.** Embed the CSP common struct rather than redeclaring
   its fields; ARCHITECTURE.md §6 lists the embeds and the supported tags. Every
   exported, non-embedded field needs a `param` tag or binding fails at runtime.
   §6 also governs what must be a parameter rather than a constant.

3. **Declare the module struct**, embedding the config struct.

4. **Implement `plugin.Module`** (`pkg/plugin/module.go`). ARCHITECTURE.md §3 lists
   every method and states what each must return — in particular, the input-targets
   method means the types a caller may aim the module at, not the types it discovers.
   Getting that wrong changes how Guard dispatches the module.

5. **Return the config from `Parameters()`** as a pointer. Never call `plugin.Bind`
   yourself; `plugin.ModuleWrapper` binds and runs post-binders before `Run`. Put
   credential construction, region resolution, and cross-field validation in a
   `PostBind` method (`plugin.PostBinder`), not in `Run`.

6. **Register in `init()`** with `plugin.Register`. Then make the package reachable:
   add a blank import to `cmd/module_imports.go` if its package is not already listed,
   and regenerate `pkg/modules/loader/loader.go` with
   `go generate ./pkg/modules/loader` — never hand-edit that file. A module with no
   blank import compiles, registers nothing, and silently does not exist at runtime.

7. **Write `Run`.** Read the bound config, build the topology, delegate to components,
   emit. Keep it thin.

8. **Choose what `Run` returns using the table in ARCHITECTURE.md §4 ("What Run
   returns").** This is the single most common source of deadlocks and truncated
   output in this codebase. The right answer depends on who closes the output
   pipeline, and there are three distinct cases. Read the table; do not guess.

9. **Emit an output type from the §8 table.** Do not invent a result type. New
   findings use `output.AurelianRisk`.

## 2. Add a component

Components hold every cloud API call and are reused across modules.

1. Create `pkg/<csp>/<service>/`, or add to the existing service package.
2. Expose a `NewXxx()` constructor taking the module's bound config plus collaborators.
3. Shape work methods so they drop into `pipeline.Pipe` as a stage with no adapter —
   ARCHITECTURE.md §5 gives the signature and two in-tree examples.
4. Page with the CSP's paginator and fan out with `ratelimit.NewCrossRegionActor`
   rather than a hand-written region loop (ARCHITECTURE.md §9 explains which paginator
   and why manual loops throttle the account).
5. No `init()`, no registry. The module constructs the component explicitly.
6. Do not import `pkg/modules/` from a component.

## 3. Add an enricher

An enricher adds properties a bulk listing cannot return.

1. Implement it in `pkg/modules/<csp>/enrichers/`.
2. Register in `init()`, keyed by resource type, using the CSP's register function —
   ARCHITECTURE.md §7 has the per-CSP table, including which type Azure operates on.
3. Mutate the resource and return. If you are deciding whether a condition holds, you
   want an evaluator, not an enricher (§7).
4. Assume best-effort: returning an error logs and forwards the resource unchanged, it
   does not fail the scan (§7). Write it so a partial result is still useful.

`pkg/modules/aws/enrichers/redshift.go` is a complete 22-line example.

## 4. Verify locally

Run all of these before opening a PR. The first two catch the wiring mistakes that
compile cleanly.

```bash
go build ./...
go generate ./pkg/modules/loader && git diff --exit-code pkg/modules/loader/loader.go
go run . list-modules | grep '<your-module-id>'
go run . <csp> <category> <your-module-id> --help
go test ./... && go test -race ./pkg/...
golangci-lint run
```

`list-modules` is the registration check: if your module is absent, step 6 is
incomplete. The `--help` invocation is the parameter check — every bound parameter
appears as a flag, so a missing flag means a missing or malformed tag.

Integration tests that stand up real infrastructure live under `test/terraform/`, in a
path mirroring the module path. See the aurelian-integration-testing skill.

## Worked example: a minimal module

`pkg/modules/aws/recon/org_policies.go` is the smallest complete module in the tree —
read it in full. It is the shape to copy when a module calls one collector and emits
one result. The load-bearing parts:

```go
package recon

func init() {
	plugin.Register(&AWSOrgPoliciesModule{})
}

type OrgPoliciesConfig struct {
	plugin.AWSReconBase
}

type AWSOrgPoliciesModule struct {
	OrgPoliciesConfig
}

// Metadata methods elided -- ARCHITECTURE.md §3 lists the full set and what
// each returns. They are fixed values: no I/O, no config reads.

func (m *AWSOrgPoliciesModule) Parameters() any {
	return &m.OrgPoliciesConfig
}

func (m *AWSOrgPoliciesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.OrgPoliciesConfig

	orgPols, err := orgpolicies.CollectOrgPolicies(cfg.Context, orgpolicies.CollectorOptions{
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return err
	}

	out.Send(orgPols)
	return nil
}
```

Note what this `Run` does and does not do. It sends directly and returns nil, which is
row 1 of the §4 table — correct precisely because nothing else is writing to `out`. A
module that instead builds stages with `pipeline.Pipe` falls under row 2 or 3 and must
return something different. Re-read §4 when you change the topology.
