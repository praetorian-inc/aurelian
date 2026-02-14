# Integration Tests

Terraform-backed integration tests for Aurelian modules. Infrastructure is automatically provisioned and destroyed.

## Usage

```bash
# Run all integration tests (provisions + destroys infrastructure automatically)
go test -tags=integration -v -timeout 30m ./test/integration/

# Run a specific test
go test -tags=integration -v -timeout 30m -run TestAWSList ./test/integration/

# Keep infrastructure between runs for faster iteration
AURELIAN_KEEP_INFRA=1 go test -tags=integration -v -timeout 30m ./test/integration/
```

Requires AWS credentials and `terraform` in PATH.

## Adding a Test

1. Create terraform in `terraform/aws/<module-name>/` with `main.tf`, `outputs.tf`, `variables.tf`
2. Use `random_id` prefix to avoid name collisions:
   ```hcl
   resource "random_id" "run" { byte_length = 4 }
   locals { prefix = "aurelian-test-${random_id.run.hex}" }
   ```
3. Export resource identifiers in `outputs.tf`
4. Write the test:
   ```go
   func TestAWSMyModule(t *testing.T) {
       fixture := NewFixture(t, "aws/my-module")
       fixture.Setup() // auto-creates and auto-destroys infrastructure

       mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "my-module")
       if !ok {
           t.Skip("my-module not registered")
       }

       results, err := mod.Run(plugin.Config{
           Args:    map[string]any{"regions": []string{"us-east-2"}},
           Context: context.Background(),
       })
       require.NoError(t, err)
       AssertResultContainsARN(t, results, fixture.Output("resource_arn"))
   }
   ```

## Terraform Modules

| Directory | Resources | Purpose |
|-----------|-----------|---------|
| `aws/list` | 2x EC2, S3, Lambda | Test resource enumeration |
