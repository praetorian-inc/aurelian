# Nebula

Nebula is a command-line tool for testing the offensive security of cloud services. It provides modules for reconnaissance, analysis, and scanning of cloud environments across multiple providers including AWS, Azure, and GCP.

For development guidance, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Features

- Comprehensive cloud resource discovery and enumeration
- Secret scanning and sensitive data detection
- Public resource exposure analysis
- Cross-platform support (AWS, Azure, GCP)
- Extensible module system

## Installation

Pre-built binaries are available in the [GitHub Releases](https://github.com/praetorian-inc/nebula/releases) section.

To build from source:
```bash
git clone https://github.com/praetorian-inc/nebula
cd nebula
go build
```

## Authentication

Nebula uses the same authentication methods as the official cloud provider CLIs:

- **AWS**: Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), credentials file (~/.aws/credentials), IAM roles
- **Azure**: Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, etc), Azure CLI credentials
- **GCP**: Environment variables (GOOGLE_APPLICATION_CREDENTIALS), gcloud CLI credentials

For details on configuring authentication, refer to:
- AWS: [Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- Azure: [Azure authentication methods](https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization)
- GCP: [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)

## Basic Usage

The basic command structure is:

```bash
nebula <provider> <category> <module> [flags]
```

Where:
- `provider` is the cloud provider (aws, azure, gcp)
- `category` is the module category (recon, analyze)  
- `module` is the specific module to run
- `flags` are module-specific configuration options

### Common Commands

List resources in an AWS account:
```bash
# List all resources in a specific region
nebula aws recon list -r us-east-1 -t AWS::S3::Bucket

# List all resources across regions
nebula aws recon list-all --scan-type full -r all
```

Find public resources:
```bash
# Check for public resources in all regions  
nebula aws recon public-resources -r all -t all

# Check specific resource type
nebula aws recon public-resources -r us-east-1 -t AWS::S3::Bucket
```

Scan for secrets:
```bash
# Scan EC2 user data for secrets
nebula aws recon find-secrets -r us-east-1 -t AWS::EC2::Instance

# Scan Lambda functions and their code
nebula aws recon find-secrets -t AWS::Lambda::Function::Code
```

### Output

Nebula supports multiple output formats including:
- JSON files for detailed data
- Markdown tables for readability
- Console output for quick results

Results are saved to the output directory (default: nebula-output/).

## Common Flags

```
Global Flags:
  --config string      Config file path (default ~/.nebula.yaml) 
  --log-level string   Log level (debug, info, warn, error)
  --no-color          Disable colored output
  --output string     Output directory (default "nebula-output")
  --quiet             Suppress user messages
  --silent            Suppress all messages except critical errors

AWS Common Flags:
  -p, --profile string    AWS credentials profile
  -r, --regions string    Comma-separated regions or 'all'
  
Azure Common Flags:
  -s, --subscription     Azure subscription ID or 'all'
  -w, --workers int      Number of concurrent workers
```

## Notes

- Always ensure you have appropriate permissions before scanning cloud environments
- Use resource type filters to limit scope when possible
- For large environments, consider using resource type or region filters to break up scans
- Monitor API rate limits, especially when scanning multiple regions