# AGENTS.md

Aurelian is a modular multi-cloud security recon framework in Go (AWS, Azure, GCP,
Kubernetes). It ships as a standalone binary.

## Required reading before you change anything

Normative and binding on new code. Not restated anywhere else.

- `ARCHITECTURE.md` — Aurelian invariants: layering, module contract, pipeline
  lifecycle, output types, boundaries.
- `DEVELOPMENT.md` — Go craft, and the DRY / YAGNI / comment principles that code
  review enforces against you.

## You must load the matching skill

Do not work from memory or from this file's summary. Before starting any task below,
read the whole `SKILL.md` and follow it. If a task matches more than one row, read
both.

| If you are… | Read first |
| --- | --- |
| Adding or changing a module, component, or enricher | `.agents/skills/aurelian-module-development/SKILL.md` |
| Writing or changing an integration test | `.agents/skills/aurelian-integration-testing/SKILL.md` |
| Reviewing a pull request | `.agents/skills/aurelian-code-review/SKILL.md` |

Skipping the skill produces code that fails review on rules stated in
`ARCHITECTURE.md` and `DEVELOPMENT.md`. Reviewers cite those documents by section, so
"I did not know" is not an available answer.

Skills are loaded by path. Do not rely on your harness auto-discovering them.

## Build and test

```bash
go build ./...
go test ./...
go generate ./pkg/modules/loader                # regenerate module blank imports
bash scripts/run-integration-tests.sh           # deploys real cloud infrastructure
bash scripts/check-architecture-refs.sh         # doc freshness gate
```

Integration tests stand up real infrastructure and cost money. Read the
aurelian-integration-testing skill before running them.
