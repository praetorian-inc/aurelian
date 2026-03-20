# Contributing to Aurelian

This doc covers dev setup, project structure, and how to add modules or components.

## Table of contents

- [Getting started](#getting-started)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Architecture overview](#architecture-overview)
- [Adding a module](#adding-a-module)
- [Adding a component](#adding-a-component)
- [Testing](#testing)
- [Code style](#code-style)
- [Commit messages](#commit-messages)
- [Pull requests](#pull-requests)
- [Reporting issues](#reporting-issues)

## Getting started

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone git@github.com:<your-username>/aurelian.git
cd aurelian
```

3. Add the upstream remote:

```bash
git remote add upstream git@github.com:praetorian-inc/aurelian.git
```

4. Create a feature branch:

```bash
git checkout -b feature/my-change
```

## Development setup

### Prerequisites

- **Go 1.24+** (the module is set to Go 1.25.3, but 1.24+ will work)
- **Terraform** (for integration test fixtures)
- **Docker** (optional, needed for graph/analyze tests using Neo4j)
- **Cloud credentials** (AWS, Azure, or GCP depending on what you're working on)

### Build and run

```bash
# Build the CLI binary
go build -o aurelian .

# Build with SQLite-backed store (for memory-constrained environments)
go build -tags cache_sqlite -o aurelian .

# Run unit tests
go test ./...

# Vet
go vet ./...
```

## Project layout

```
cmd/                              CLI entry point and subcommands
pkg/
  modules/<csp>/<category>/       Modules (entry points)
    aws/recon/                    AWS reconnaissance modules
    aws/analyze/                  AWS graph analysis modules
    aws/enrichers/                AWS enrichment plugins
    aws/rules/                    AWS rule definitions
    azure/recon/                  Azure reconnaissance modules
    azure/enrichers/              Azure enrichment plugins
    azure/evaluators/             Azure evaluation plugins
    gcp/recon/                    GCP reconnaissance modules
    gcp/enrichers/                GCP enrichment plugins
  aws/                            AWS components (cloudcontrol, enrichment, gaad, iam, publicaccess, etc.)
  azure/                          Azure components (resourcegraph, subscriptions, armenum, etc.)
  gcp/                            GCP components (enumeration, hierarchy, publicaccess, etc.)
  pipeline/                       Pipeline concurrency primitive
  plugin/                         Module interface, registry, parameter binding
  model/                          AurelianModel output type
  store/                          Generic key-value map (in-memory or SQLite)
  ratelimit/                      Paginator, CrossRegionActor
  output/                         Output formatting
  secrets/                        Secret detection
test/
  terraform/<csp>/<category>/<module>/   Terraform fixtures for integration tests
  testutil/                              Test helpers (fixtures, assertions, Neo4j)
```

## Architecture overview

Aurelian has three core patterns: **Modules**, **Pipelines**, and **Components**. Modules are entry points, Pipelines are the concurrency primitive, and Components are reusable building blocks.

For detailed architecture documentation including pipeline lifecycle rules, parameter binding, and core utilities, see [DEVELOPMENT.md](DEVELOPMENT.md).

### Modules

A Module implements `plugin.Module` and is the top-level unit of work. Modules are registered in `init()`, discovered automatically, and wired into the CLI. They emit results into a `*pipeline.P[model.AurelianModel]`.

### Pipelines

`pipeline.P[T]` is a generic, unbuffered channel wrapper providing streaming with backpressure. The universal contract is `func(input T, out *pipeline.P[U]) error`.

### Components

Reusable utility types in `pkg/<csp>/<component>/` whose methods conform to the pipeline function signature. Components are stateless processors wired into modules via `pipeline.Pipe`.

### Composition

Modules orchestrate components through pipeline chains. See [DEVELOPMENT.md](DEVELOPMENT.md) for composition examples and pipeline lifecycle rules.

## Adding a module

Modules live in `pkg/modules/<csp>/<category>/`. They all follow the same pattern:

1. Create the file, e.g. `pkg/modules/aws/recon/my_module.go`:

```go
package recon

import (
    "github.com/praetorian-inc/aurelian/pkg/model"
    "github.com/praetorian-inc/aurelian/pkg/pipeline"
    "github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
    plugin.Register(&MyModule{})
}

type MyModule struct {
    plugin.AWSCommonRecon // embed shared parameter group
}

func (m *MyModule) ID() string                      { return "my-module" }
func (m *MyModule) Name() string                    { return "My Module" }
func (m *MyModule) Description() string             { return "Discovers something useful" }
func (m *MyModule) Platform() plugin.Platform       { return plugin.PlatformAWS }
func (m *MyModule) Category() plugin.Category       { return plugin.CategoryRecon }
func (m *MyModule) OpsecLevel() string              { return "read-only" }
func (m *MyModule) Authors() []string               { return []string{"your-name"} }
func (m *MyModule) References() []string            { return nil }
func (m *MyModule) SupportedResourceTypes() []string { return []string{plugin.AnyResourceType} }
func (m *MyModule) Parameters() any                 { return &m.AWSCommonRecon }

func (m *MyModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
    // Orchestrate components through pipelines.
    // See DEVELOPMENT.md for pipeline lifecycle rules.
    return nil
}
```

2. The module is automatically discovered via `init()` registration — no additional wiring needed.

3. Write an integration test (see [Testing](#integration-tests)).

**Key rules:**
- `SupportedResourceTypes()` declares **input targets**, not internally-discovered types
- Emit results via `out.Send()` — never return results directly
- Use named methods in `pipeline.Pipe` — no inline closures
- See [DEVELOPMENT.md](DEVELOPMENT.md) for `out.Wait()` vs `return nil` rules

## Adding a component

Components live in `pkg/<csp>/<component>/` and expose pipeline-compatible methods:

1. Create the package, e.g. `pkg/aws/mycomponent/mycomponent.go`:

```go
package mycomponent

import "github.com/praetorian-inc/aurelian/pkg/pipeline"

type MyComponent struct {
    // configuration fields
}

func NewMyComponent(opts Options) *MyComponent {
    return &MyComponent{/* ... */}
}

// Method conforms to pipeline function signature
func (c *MyComponent) Process(input InputType, out *pipeline.P[OutputType]) error {
    // process input, send results to out
    return nil
}
```

2. Wire into a module via `pipeline.Pipe(source, component.Process, dest)`.

**Key rules:**
- Methods must accept exactly two arguments: a single input struct and the output pipeline
- If a method needs multiple domain parameters, bundle them into an input struct
- Don't create interfaces solely for unit test mocking — use integration tests

## Testing

### Unit tests

```bash
# All unit tests
go test ./...

# Specific package
go test -v ./pkg/pipeline/...
```

Use `testify/assert` and `testify/require`. Use table-driven tests with descriptive subtest names.

### Integration tests

Integration tests run modules against live cloud infrastructure provisioned via Terraform fixtures. See [DEVELOPMENT.md](DEVELOPMENT.md) for full details.

```bash
# AWS recon tests
go test -tags=integration -v -timeout 30m ./pkg/modules/aws/recon/

# Azure recon tests
go test -tags=integration -v -timeout 30m ./pkg/modules/azure/recon/

# Graph/analyze tests (requires Docker for Neo4j)
go test -tags=integration -v -timeout 30m ./pkg/modules/aws/analyze/

# Specific test
go test -tags=integration -v -timeout 30m -run TestMyModule ./pkg/modules/aws/recon/
```

**Requirements:**
- Cloud credentials configured (AWS, Azure, or GCP)
- `terraform` in PATH
- Docker (for graph/analyze tests)
- 30-minute timeout

**Key conventions:**
- Build tag `//go:build integration` as first line, before `package`
- Test file: `<module_name>_integration_test.go` in same package
- Terraform fixtures use `backend "s3" {}` — never local backend
- Fixture dir mirrors module path: `aws/recon/my_module.go` → `test/terraform/aws/recon/my-module/`
- Run module once, use `t.Run()` subtests for per-resource assertions
- Component tests reuse existing module fixtures

## Code style

### Formatting

All code must pass `go vet`. Format with `gofmt` / `goimports`.

### Go version

Use modern Go 1.24+ idioms:
- `slices`, `maps`, `cmp` packages over manual loops
- `min`/`max`/`clear` builtins
- `range n` over `for i := 0; i < n; i++`
- `cmp.Or` for defaults
- `errors.Is`/`errors.As`/`%w` for error handling
- `strings.Cut`/`CutPrefix` for string parsing
- `errgroup` over `sync.WaitGroup` + channels

### Guidelines

- Keep functions focused and readable.
- Check all errors. Use `require.NoError(t, err)` in tests.
- Avoid global mutable state outside of `init()` registrations.
- Use `context.Context` for cancellation and timeouts in all I/O paths.
- Prefer returning `(result, error)` over panicking.
- Use AWS SDK v2 only — v1 (`github.com/aws/aws-sdk-go`) is deprecated.
- Use `ratelimit.NewCrossRegionActor()` — not `ratelimit.Global()`.

## Commit messages

This project uses **conventional commits**. Each commit message should have a type prefix:

| Prefix | Use for |
|--------|---------|
| `feat:` | New features or modules |
| `fix:` | Bug fixes |
| `refactor:` | Code restructuring without behavior change |
| `chore:` | Build, CI, dependency, or tooling changes |
| `test:` | Adding or updating tests |
| `docs:` | Documentation changes |

Concise summary in the imperative mood. Scope by CSP/module when relevant. Add detail in the body if the "why" isn't obvious from the diff.

```
feat(aws): add Redshift public access detection to public-resources

fix(azure/find-secrets): fix webapp-hostkeys 404, Cosmos cross-partition query

refactor(gcp): extract shared enrichment logic into component
```

## Pull requests

1. One logical change per PR. If you're fixing a bug and adding a feature, split them.
2. `go test ./...` and `go vet ./...` must pass.
3. Describe what changed and why. Link to related issues.
4. Add tests for new functionality. Modules need integration tests.
5. Keep diffs reviewable. Avoid unrelated formatting changes.

### PR checklist

- [ ] Tests pass (`go test ./...`)
- [ ] Vet passes (`go vet ./...`)
- [ ] New module registered via `plugin.Register()` in `init()`
- [ ] Integration test written with Terraform fixture
- [ ] Commit messages follow conventional commit format
- [ ] Pipeline lifecycle rules followed (see [DEVELOPMENT.md](DEVELOPMENT.md))

## Reporting issues

When opening an issue, include:

- What you expected vs. what happened
- Steps to reproduce (CLI command, flags, cloud environment details)
- Aurelian version (`git describe --tags`)
- Go version (`go version`)
- OS and architecture

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a public issue.
