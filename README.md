# Diocletian

Diocletian is a command-line security scanning tool built on the Janus framework for testing cloud environments. It provides modular security testing capabilities across AWS, Azure, and GCP with extensible link-based architecture.

For development guidance, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Documentation

📖 **[Full CLI Documentation](docs/)** - Complete command reference with examples

## Features

- **Multi-Cloud Support**: AWS, Azure, GCP, and SaaS platforms
- **Modular Architecture**: Built on Janus framework with composable links
- **Security Scanning**: Resource discovery, secret detection, public exposure analysis
- **Flexible Output**: JSON, Markdown, and console formats
- **MCP Integration**: Model Context Protocol server for AI assistants

## Installation

**From Source:**
```bash
git clone https://github.com/praetorian-inc/diocletian
cd diocletian
go build
```

**Docker:**
```bash
docker build -t diocletian .
docker run --rm -v ~/.aws:/root/.aws diocletian aws recon whoami
```

**Pre-built binaries** available in [GitHub Releases](https://github.com/praetorian-inc/diocletian/releases).

**Dependencies** secret scanning is done using [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) and must be available in your `$PATH`.

## Authentication

Diocletian uses standard cloud provider authentication:

- **AWS**: Environment variables, credentials file (~/.aws/credentials), IAM roles
- **Azure**: Environment variables, Azure CLI, managed identity
- **GCP**: Service account keys, application default credentials
- **Docker**: Registry credentials via --docker-user and --docker-password flags

## Basic Usage

```bash
diocletian <provider> <category> <module> [flags]
```

**Examples:**
```bash
# Check AWS account identity
diocletian aws recon whoami

# List all S3 buckets across regions
diocletian aws recon list -t AWS::S3::Bucket -r all

# Find secrets in Lambda functions
diocletian aws recon find-secrets -t AWS::Lambda::Function

# Discover public Azure resources  
diocletian azure recon public-resources -s subscription-id

# Get GCP project information
diocletian gcp recon projects-list

# Analyze Docker container for secrets
diocletian saas recon docker-dump -i nginx:latest
```

## Common Commands

**AWS Reconnaissance:**
```bash
# Account information and permissions
diocletian aws recon account-auth-details
diocletian aws recon whoami

# Resource discovery
diocletian aws recon list-all-resources -r us-east-1
diocletian aws recon public-resources -r all

# Secrets scanning
diocletian aws recon find-secrets -t all -r all
diocletian aws recon find-secrets -t AWS::Lambda::Function -r us-east-2
```

**Azure Reconnaissance:**
```bash
# Environment details
diocletian azure recon summary -s subscription-id

# Resource enumeration  
diocletian azure recon list-all-resources -s subscription-id
diocletian azure recon public-resources -s all

# DevOps secrets scanning
diocletian azure recon devops-secrets --organization org-name
```

**SaaS Reconnaissance:**
```bash
# Docker container analysis and secret scanning
diocletian saas recon docker-dump -i image-name
```

**Analysis Modules:**
```bash
# AWS key analysis
diocletian aws analyze access-key-to-account-id -k AKIA...
diocletian aws analyze known-account -a 123456789012

# IP analysis
diocletian aws analyze ip-lookup -i 1.2.3.4
```

## Output and Results

**Output Formats:**
- **Console**: Real-time progress and summaries
- **JSON**: Structured data in `diocletian-output/` directory
- **Markdown**: Human-readable tables

**Common Flags:**
```bash
# Global options
--log-level string    Log level (debug, info, warn, error)
--output string       Output directory (default "diocletian-output")
--quiet              Suppress user messages
--no-color           Disable colored output

# Provider-specific  
-r, --regions string  AWS regions ('all' or comma-separated)
-s, --subscription    Azure subscription ID
-t, --resource-type   Cloud resource type filter
-i, --image string    Docker image name for SaaS modules
```

## MCP Server

Diocletian provides an MCP (Model Context Protocol) server for AI assistants:

**Stdio Server:**
```bash
diocletian mcp-server
```

**HTTP Server:**
```bash
diocletian mcp-server --http --addr :8080
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "diocletian": {
      "command": "/path/to/diocletian", 
      "args": ["mcp-server"]
    }
  }
}
```

## Security Notes

- **Permissions**: Ensure appropriate read-only permissions before scanning. Note: Many AWS modules use the [Cloud Control API](https://aws.amazon.com/cloudcontrolapi/) which requires `cloudformation:ListResources` and `cloudformation:GetResources`.
- **Scope Control**: Use resource type and region filters to limit scan scope

## Architecture

Diocletian uses Praetorian's  [Janus Framework](https://github.com/praetorian-inc/janus-framework).
- **Links**: Individual processing units that can be chained together
- **Modules**: Pre-configured chains for specific security testing scenarios
- **Outputters**: Pluggable output processing for different formats
- **Registry**: Dynamic module discovery and CLI generation

For development details, see [DEVELOPMENT.md](DEVELOPMENT.md).
