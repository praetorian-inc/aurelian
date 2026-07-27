# AGENTS.md

Aurelian is a modular multi-cloud security recon framework in Go (AWS, Azure, GCP,
Kubernetes). It ships as a standalone binary.

## Rules

- Architecture and Aurelian invariants: ARCHITECTURE.md
- Go craft, DRY, YAGNI, comments: DEVELOPMENT.md

Both are normative and binding on new code. Read the relevant one before changing
code. Neither is restated anywhere else — this file points, it does not duplicate.

## Skills

Load the one matching your task from `.agents/skills/<name>/SKILL.md`:

| Task | Skill |
| --- | --- |
| Add or change a module, component, enricher | aurelian-module-development |
| Write an integration test | aurelian-integration-testing |
| Review a pull request | aurelian-code-review |

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
