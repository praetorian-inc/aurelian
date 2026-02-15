# Functional Tests

This directory contains functional tests for Nebula recon modules that require live cloud environments.

## Test Structure

```
functional/
├── README.md                     # This file
├── aws_recon_test.go            # AWS recon module tests
├── azure_recon_test.go          # Azure recon module tests  
├── gcp_recon_test.go            # GCP recon module tests
├── testdata/                    # Expected output validation data
│   ├── aws/                     # AWS expected outputs
│   ├── azure/                   # Azure expected outputs
│   └── gcp/                     # GCP expected outputs
└── infrastructure/              # Test infrastructure configurations
    ├── aws/                     # AWS test infrastructure
    ├── azure/                   # Azure test infrastructure
    └── gcp/                     # GCP test infrastructure
```

## Running Tests

### Prerequisites

**AWS Tests:**
- AWS credentials configured (profile "terraform" recommended)
- Terraform installed for infrastructure deployment
- Appropriate IAM permissions for resource creation

**Azure Tests:**
- Azure CLI authenticated with subscription `355e78a0-4c5e-4de3-9980-6a35cae86f01`
- Terraform installed with Azure provider
- Appropriate RBAC permissions

**GCP Tests:**
- GCP credentials configured  
- Terraform installed with GCP provider
- Appropriate IAM permissions

### Execution

Run all functional tests (requires cloud credentials):
```bash
go test -v ./test/functional/
```

Run specific cloud provider tests:
```bash
# AWS only
go test -v ./test/functional/ -run TestAWS

# Azure only  
go test -v ./test/functional/ -run TestAzure

# GCP only
go test -v ./test/functional/ -run TestGCP
```

Run with infrastructure deployment (slower but comprehensive):
```bash
go test -v ./test/functional/ -deploy-infra=true
```

### Test Behavior

- **Infrastructure**: Tests automatically deploy required cloud resources using Terraform
- **Validation**: Compares actual Nebula outputs against expected results in `testdata/`
- **Cleanup**: Resources are automatically destroyed after test completion
- **Isolation**: Each test creates uniquely named resources to avoid conflicts
- **Skipping**: Tests are skipped if cloud credentials are not available

### Test Secret

Tests use the standard test secret for validation:
```
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
```

This secret is embedded in test infrastructure and should be discovered by secret-scanning modules.

### Expected Outputs

Each module test validates specific outputter types:

- **RuntimeJSONOutputter**: JSON structure and resource metadata
- **NPFindingsConsoleOutputter**: NoseyParker findings with correct provenance  
- **RiskConsoleOutputter**: Risk assessment data
- **MarkdownTableConsoleOutputter**: Formatted summary tables
- **URLConsoleOutputter**: Valid console URLs

### Troubleshooting

**Test Skipped**: Ensure cloud credentials are properly configured
**Infrastructure Errors**: Check Terraform configurations and IAM/RBAC permissions
**Validation Failures**: Compare actual vs expected outputs in test logs
**Resource Conflicts**: Ensure unique resource naming and proper cleanup