# Integration Tests

Terraform-backed integration tests for Aurelian modules. Infrastructure is automatically provisioned and destroyed.

## Directory Structure

```
test/integration/
  testutil/                    # Shared helpers (non-test Go files)
    fixture.go                 # TerraformFixture
    assertions.go              # AssertResultContains*
    neo4j.go                   # StartNeo4jContainer, ClearNeo4jDatabase

  aws/
    recon/                     # Tests for pkg/modules/aws/recon (Terraform only, NO Neo4j)
      list_test.go             # TestAWSList
      ec2_test.go              # TestAWSEC2Enumeration*
      gaad_test.go             # TestAWSAccountAuthDetails
      terraform/aws/
        list/                  # EC2, S3, Lambda test infrastructure
        gaad/                  # IAM user, role, group, policy test infrastructure

    analyze/                   # Tests for pkg/modules/aws/analyze + pkg/graph (WITH Neo4j)
      testmain_test.go         # TestMain: starts shared Neo4j container
      neo4j_test.go            # TestNeo4jAdapter_*, TestGraphFormatter_*, TestEnrichmentQueries
      validation_test.go       # TestGraphValidation_PrivescDetection (18 subtests)
      terraform/aws/
        graph/                 # IAM privilege escalation test infrastructure
```

## Usage

```bash
# Run ALL integration tests
go test -tags=integration -v -timeout 30m ./test/integration/...

# Run only recon tests (NO Neo4j container started)
go test -tags=integration -v -timeout 30m ./test/integration/aws/recon/

# Run only analyze/graph tests (starts Neo4j container)
go test -tags=integration -v -timeout 30m ./test/integration/aws/analyze/

# Run a specific test
go test -tags=integration -v -timeout 30m -run TestAWSList ./test/integration/aws/recon/

# Keep infrastructure between runs for faster iteration
AURELIAN_KEEP_INFRA=1 go test -tags=integration -v -timeout 30m ./test/integration/aws/recon/
```

Requires AWS credentials and `terraform` in PATH. Analyze tests additionally require Docker (for Neo4j container via testcontainers).

## Adding a Test

### Recon test (no Neo4j)

1. Create terraform in `aws/recon/terraform/aws/<module-name>/` with `main.tf`, `outputs.tf`, `variables.tf`
2. Use `random_id` prefix to avoid name collisions:
   ```hcl
   resource "random_id" "run" { byte_length = 4 }
   locals { prefix = "aurelian-test-${random_id.run.hex}" }
   ```
3. Export resource identifiers in `outputs.tf`
4. Write the test in `aws/recon/`:
   ```go
   package recon

   func TestAWSMyModule(t *testing.T) {
       fixture := testutil.NewFixture(t, "aws/my-module")
       fixture.Setup()

       mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "my-module")
       if !ok { t.Skip("my-module not registered") }

       results, err := mod.Run(plugin.Config{
           Args:    map[string]any{"regions": []string{"us-east-2"}},
           Context: context.Background(),
       })
       require.NoError(t, err)
       testutil.AssertResultContainsARN(t, results, fixture.Output("resource_arn"))
   }
   ```

### Analyze test (with Neo4j)

1. Create terraform in `aws/analyze/terraform/aws/<module-name>/`
2. Write the test in `aws/analyze/` — use `sharedNeo4jBoltURL` and `testutil.ClearNeo4jDatabase()`

## Terraform Modules

| Directory | Resources | Purpose |
|-----------|-----------|---------|
| `aws/recon/terraform/aws/list` | 2x EC2, S3, Lambda | Test resource enumeration |
| `aws/recon/terraform/aws/gaad` | IAM user, role, group, policy | Test account auth details |
| `aws/analyze/terraform/aws/graph` | 18 IAM privilege escalation scenarios | Test graph analysis pipeline |
