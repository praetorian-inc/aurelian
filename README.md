# aurelian

aurelian is a command-line security scanning tool built on the Janus framework for testing cloud environments. It provides modular security testing capabilities across AWS, Azure, and GCP with extensible link-based architecture.

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
git clone https://github.com/praetorian-inc/aurelian
cd aurelian
go build
```

**Docker:**
```bash
docker build -t aurelian .
docker run --rm -v ~/.aws:/root/.aws aurelian aws recon whoami
```

**Pre-built binaries** available in [GitHub Releases](https://github.com/praetorian-inc/aurelian/releases).

**Dependencies** secret scanning is done using [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) and must be available in your `$PATH`.

## Authentication

aurelian uses standard cloud provider authentication:

- **AWS**: Environment variables, credentials file (~/.aws/credentials), IAM roles
- **Azure**: Environment variables, Azure CLI, managed identity
- **GCP**: Service account keys, application default credentials
- **Docker**: Registry credentials via --docker-user and --docker-password flags

## Basic Usage

```bash
aurelian <provider> <category> <module> [flags]
```

**Examples:**
```bash
# Check AWS account identity
aurelian aws recon whoami

# List all S3 buckets across regions
aurelian aws recon list -t AWS::S3::Bucket -r all

# Find secrets in Lambda functions
aurelian aws recon find-secrets -t AWS::Lambda::Function

# Discover public Azure resources  
aurelian azure recon public-resources -s subscription-id

# Get GCP project information
aurelian gcp recon projects-list

# Analyze Docker container for secrets
aurelian saas recon docker-dump -i nginx:latest
```

## Common Commands

**AWS Reconnaissance:**
```bash
# Account information and permissions
aurelian aws recon account-auth-details
aurelian aws recon whoami

# Resource discovery
aurelian aws recon list-all-resources -r us-east-1
aurelian aws recon public-resources -r all

# Secrets scanning
aurelian aws recon find-secrets -t all -r all
aurelian aws recon find-secrets -t AWS::Lambda::Function -r us-east-2
```

**Azure Reconnaissance:**
```bash
# Environment details
aurelian azure recon summary -s subscription-id

# Resource enumeration  
aurelian azure recon list-all-resources -s subscription-id
aurelian azure recon public-resources -s all

# DevOps secrets scanning
aurelian azure recon devops-secrets --organization org-name
```

**SaaS Reconnaissance:**
```bash
# Docker container analysis and secret scanning
aurelian saas recon docker-dump -i image-name
```

**Analysis Modules:**
```bash
# AWS key analysis
aurelian aws analyze access-key-to-account-id -k AKIA...
aurelian aws analyze known-account -a 123456789012

# IP analysis
aurelian aws analyze ip-lookup -i 1.2.3.4
```

## Output and Results

**Output Formats:**
- **Console**: Real-time progress and summaries
- **JSON**: Structured data in `aurelian-output/` directory
- **Markdown**: Human-readable tables

**Common Flags:**
```bash
# Global options
--log-level string    Log level (debug, info, warn, error)
--output string       Output directory (default "aurelian-output")
--quiet              Suppress user messages
--no-color           Disable colored output

# Provider-specific  
-r, --regions string  AWS regions ('all' or comma-separated)
-s, --subscription    Azure subscription ID
-t, --resource-type   Cloud resource type filter
-i, --image string    Docker image name for SaaS modules
```

## MCP Server

aurelian provides an MCP (Model Context Protocol) server for AI assistants:

**Stdio Server:**
```bash
aurelian mcp-server
```

**HTTP Server:**
```bash
aurelian mcp-server --http --addr :8080
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "aurelian": {
      "command": "/path/to/aurelian", 
      "args": ["mcp-server"]
    }
  }
}
```

## Security Notes

- **Permissions**: Ensure appropriate read-only permissions before scanning. Note: Many AWS modules use the [Cloud Control API](https://aws.amazon.com/cloudcontrolapi/) which requires `cloudformation:ListResources` and `cloudformation:GetResources`.
- **Scope Control**: Use resource type and region filters to limit scan scope

## Architecture

aurelian uses Praetorian's  [Janus Framework](https://github.com/praetorian-inc/janus-framework).
- **Links**: Individual processing units that can be chained together
- **Modules**: Pre-configured chains for specific security testing scenarios
- **Outputters**: Pluggable output processing for different formats
- **Registry**: Dynamic module discovery and CLI generation

For development details, see [DEVELOPMENT.md](DEVELOPMENT.md).
