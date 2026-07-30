---
name: aurelian-integration-testing
description: Use when writing, modifying, running, or tearing down integration tests for Aurelian modules and components - covers Terraform fixtures, test structure, assertion quality, Neo4j graph tests, executing the suite, and destroying fixtures
license: Apache-2.0
---

# Aurelian Integration Testing

Integration tests run modules and components against live cloud infrastructure
provisioned by Terraform fixtures.

## Hard rules

- **Integration tests deploy real infrastructure.** No mocks, fakes, or stubs in a
  `//go:build integration` file. Mock-based logic belongs in an untagged unit test in
  the same package.
- Directory layout, fixture path, and where module vs component code lives are
  architecture invariants. See ARCHITECTURE.md §2. Do not restate them in tests.
- Never hardcode an expected value that Terraform already knows. Read it from a
  fixture output.

## Conventions

| Item | Pattern |
| --- | --- |
| Test file | `<module_name>_integration_test.go`, in the same package as the code under test |
| Build tag | `//go:build integration` — first line, blank line, then `package` |
| Fixture directory | Mirrors the module path. See ARCHITECTURE.md §2. |
| Fixture path argument | Relative to `test/terraform`, e.g. `"aws/recon/graph"` |

## Workflow

1. Identify the module or component under test.
2. Create or reuse a Terraform fixture.
3. Write the test.
4. Run it.
5. Tear down (or deliberately leave the fixture up).

## 1. Identify the target

Modules are addressed by the triple the module registers with: platform, category,
module ID. Read the module's `init()` registration for the exact ID — do not guess it
from the filename.

Components are called directly. They have no registry entry.

## 2. Create or reuse the fixture

Reuse first. A component almost never needs its own fixture — point it at a module
fixture that already provisions the resources it reads.

**Backend is mandatory and must be S3:**

```hcl
terraform {
  backend "s3" {}
}
```

Fixture setup runs `terraform init -backend-config` with `bucket`, `region`, and `key`.
Those flags are only valid when the backend type is S3. A `backend "local" {}` fixture
fails at init. Leave the block empty — values are injected.

Fixture rules:

- Derive resource names from a `prefix` variable or local so parallel stacks do not
  collide. Build the prefix from caller identity where possible.
- Sanitize the prefix for CSP naming constraints. Azure storage accounts are 3–24
  characters, lowercase alphanumeric only.
- Export every identifier the test asserts on as an output — ARNs, IDs, names.
- Provision *diverse* resources. A module that enumerates ten resource types needs a
  fixture with ten resource types, each with its own assertion.
- Keep retention and TTL short to save cost. Ephemeral data is re-injected by the test
  (below), not preserved by the fixture.

```hcl
output "resource_ids" {
  value = [aws_instance.test.id]
}
```

## 3. Write the test

Canonical module test:

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
    fixture := testutil.NewAWSFixture(t, "aws/recon/graph")
    fixture.Setup()

    mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "module-id")
    require.True(t, ok, "module-id not registered in plugin system")

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
    for _, id := range fixture.OutputList("resource_ids") {
        testutil.AssertResultContainsString(t, results, id)
    }
}
```

A component test is the same shape minus the registry lookup — instantiate the
component and call its method. Parameter structs such as `plugin.AWSCommonRecon` carry
regions and other common inputs.

### Fixture API

| Call | Returns | Use |
| --- | --- | --- |
| `testutil.NewAWSFixture(t, dir)` | Fixture | AWS fixture; `dir` relative to `test/terraform` |
| `testutil.NewAzureFixture(t, dir)` | Fixture | Azure fixture |
| `testutil.NewGCPFixture(t, dir)` | Fixture | GCP fixture |
| `fixture.Setup()` | — | Deploy or reuse. Hash-based: redeploys only when the template changes. |
| `fixture.Output(key)` | `string` | One Terraform output |
| `fixture.OutputList(key)` | `[]string` | List output |
| `fixture.OutputMap(key)` | `map[string]string` | Map output |

### Assertion helpers

Defined in `test/testutil`:

```go
testutil.AssertMinResults(t, results, 5)
testutil.AssertResultContainsARN(t, results, arn)
testutil.AssertResultContainsString(t, results, substr)
testutil.AssertNoDuplicateResults(t, results)
testutil.RunAndCollect(t, mod, cfg)   // registry lookup already done
```

For typed checks, type-switch to the concrete output type and use testify directly.

### Collecting results

One type — collect:

```go
results, err := p2.Collect()
require.NoError(t, err)
```

Several types — range and switch, then wait:

```go
var entities []output.AWSIAMResource
var rels []output.AWSIAMRelationship
for m := range p2.Range() {
    switch v := m.(type) {
    case output.AWSIAMResource:
        entities = append(entities, v)
    case output.AWSIAMRelationship:
        rels = append(rels, v)
    }
}
require.NoError(t, p2.Wait())
```

### Subtests

Run the module **once**, then split assertions into subtests. Clear diagnostics, no
repeated cloud calls.

```go
results, err := testutil.RunAndCollect(t, mod, cfg)
require.NoError(t, err)

t.Run("discovers storage accounts", func(t *testing.T) {
    testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
})
```

Call `fixture.Setup()` once before the subtests, never per-subtest. Do not retry module
runs — fixtures are long-lived and resources have already propagated. Name subtests for
behavior (`"discovers X"`), not raw resource IDs.

### Ephemeral fixture data

Fixtures are long-lived, so short-retention data (CloudWatch log events, Step Functions
execution history) expires and dependent subtests fail quietly. Re-inject it between
`fixture.Setup()` and the module run, with an idempotent helper that no-ops when the
data is already present:

```go
testutil.EnsureLogEvent(t, "us-east-2",
    fixture.Output("log_group_name"),
    fixture.Output("log_stream_name"),
    fixture.Output("log_event_message"),
)
```

Every input comes from a fixture output. Add a Terraform output rather than hardcoding
a message string.

### Enricher dependencies

If the module under test depends on enrichers, blank-import them so their `init()`
registration runs:

```go
import _ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
```

## 4. Test quality

**`require` vs `assert`.** `require` for preconditions — the rest of the test is
meaningless without them, so fail fast. `assert` for independent verifications, so one
run reports every failure.

```go
require.NoError(t, err)
require.True(t, ok, "module not registered")
assert.NotEmpty(t, v.RiskName, "risk name should be populated")
assert.NotEmpty(t, v.Severity, "severity should be populated")
```

**Assert structurally.** `len(results) > 0` is not an assertion. Type-switch to the
concrete type and check named fields. For risk-producing modules check risk name,
severity, populated context, and the impacted resource identifier.

**Assert against fixture outputs.** Prove the module found *the intentionally vulnerable
resource*, not that it found something.

**Cover negative paths.** Assert what must NOT happen: a compliant resource produces no
finding, an error surfaces instead of being swallowed, a duplicate registration panics.

**Assert invariants across the whole result set**, not just spot checks:

```go
t.Run("no duplicate resources", func(t *testing.T) {
    seen := map[string]bool{}
    for _, r := range resources {
        require.False(t, seen[r.ResourceID], "duplicate resource: %s", r.ResourceID)
        seen[r.ResourceID] = true
    }
})
```

**Table-driven for pure functions** with many input/output pairs. Individual functions
for behavior with side effects.

**Reset shared state.** Any test touching a package-level registry or singleton resets
first — otherwise the suite develops ordering dependencies. `plugin.ResetRegistry` for
the module registry.

**Do not write thin tests.** One to three assertions against real infrastructure is
almost certainly insufficient. More assertions on a single module run are cheap;
re-running modules is expensive.

| Module type | Minimum |
| --- | --- |
| Resource enumeration | 5+ distinct resource checks |
| Risk or finding detection | 3–5+ unique risk outputs, with field validation |
| Public resource detection | 3–5+ resource checks plus risk field correctness |

## 5. Graph tests (Neo4j)

Graph analysis modules need a Neo4j container via testcontainers. Start it in the test
and register cleanup:

```go
boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
require.NoError(t, err)
t.Cleanup(cleanup)

testutil.ClearNeo4jDatabase(t, boltURL)
```

Reset the database before each test that shares a container. Docker is required. Use
`-timeout 30m` — IAM provisioning alone can take 15–30 minutes.

| Aspect | Convention |
| --- | --- |
| Node labels | `User`, `Role`, `Group`, `Resource`, `ServicePrincipal` |
| Relationship types | Uppercase with underscores: `IAM_CREATEPOLICYVERSION` |
| GAAD properties | PascalCase: `Arn`, `UserName`, `RoleName` |
| Cloud resource properties | lowercase: `arn`, `region`, `account_id` |
| Isolation | Filter Cypher by the fixture's `random_suffix` output |

## 6. Run

```bash
scripts/run-integration-tests.sh                                    # everything
scripts/run-integration-tests.sh ./pkg/modules/aws/recon/...        # one package
scripts/run-integration-tests.sh ./pkg/modules/aws/recon/... -v -run TestMyModule -timeout 30m
scripts/run-integration-tests.sh --destroy                          # redeploy fixtures first
```

Flags: `-v`, `-run PATTERN`, `-count N`, `-timeout DURATION`, `--destroy`. The script
loads credentials from `.env.integration`.

Equivalent direct invocation:

```bash
go test -tags=integration -v -timeout 30m -run TestMyModule ./pkg/modules/aws/recon/
```

Requirements: cloud credentials for the CSP under test, `terraform` in `PATH`, Docker
for graph tests, and a 30-minute timeout.

## 7. Tear down

Fixtures persist between runs by design — redeploying costs more than leaving them up,
and `fixture.Setup()` reuses a stack whose template hash is unchanged.

```bash
AURELIAN_DESTROY_FIXTURES=1 go test -tags=integration ./...   # destroy + redeploy
scripts/teardown-integration-fixtures.sh                      # DRY RUN, lists targets
scripts/teardown-integration-fixtures.sh --yes                # destroy all fixtures
scripts/teardown-integration-fixtures.sh --yes aws/           # only keys matching aws/
```

Teardown destroys from the artifacts actually applied, pulled from S3 remote state, then
removes the hash marker so the next run redeploys cleanly. Azure and GCP fixtures need
valid `az` / `gcloud` credentials to destroy; AWS-only teardown needs `AWS_PROFILE`.

## Verify before claiming done

```bash
go test ./...                                              # unit tests still pass
go vet -tags=integration ./pkg/modules/<csp>/<category>/   # the test compiles
scripts/run-integration-tests.sh ./pkg/modules/<csp>/<category>/... -v -run TestMyModule
```

`go build` does not compile tagged test files. `go vet -tags=integration` is the only
cheap check that the test compiles at all — run it before spending money on cloud
resources.

## Common mistakes

- Mocking a cloud API inside a tagged integration test.
- A thin test: one assertion, no field checks, no negative path.
- Hardcoded ARNs, IDs, or region names instead of fixture outputs.
- A dedicated fixture for a component that could reuse a module's.
- Re-running the module per subtest instead of once up front.
- `backend "local" {}` in a fixture.
- Forgetting the blank enricher import, then debugging an empty result set.
