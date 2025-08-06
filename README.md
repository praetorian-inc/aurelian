# Nebula

Nebula is a command-line security scanning tool built on the Janus framework for testing cloud environments. It provides modular security testing capabilities across AWS, Azure, and GCP with extensible link-based architecture.

For development guidance, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Features

- **Multi-Cloud Support**: AWS, Azure, GCP, and SaaS platforms
- **Modular Architecture**: Built on Janus framework with composable links
- **Security Scanning**: Resource discovery, secret detection, public exposure analysis
- **Flexible Output**: JSON, Markdown, and console formats
- **MCP Integration**: Model Context Protocol server for AI assistants

## Installation

**From Source:**
```bash
git clone https://github.com/praetorian-inc/nebula
cd nebula
go build
```

**Docker:**
```bash
docker build -t nebula .
docker run --rm -v ~/.aws:/root/.aws nebula aws recon whoami
```

**Pre-built binaries** available in [GitHub Releases](https://github.com/praetorian-inc/nebula/releases).

**Dependencies** secret scanning is done using [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) and must be available in your `$PATH`.

## Authentication

Nebula uses standard cloud provider authentication:

- **AWS**: Environment variables, credentials file (~/.aws/credentials), IAM roles
- **Azure**: Environment variables, Azure CLI, managed identity
- **GCP**: Service account keys, application default credentials

## Basic Usage

```bash
nebula <provider> <category> <module> [flags]
```

**Examples:**
```bash
# Check AWS account identity
nebula aws recon whoami

# List all S3 buckets across regions
nebula aws recon list -t AWS::S3::Bucket -r all

# Find secrets in Lambda functions
nebula aws recon find-secrets -t AWS::Lambda::Function

# Discover public Azure resources  
nebula azure recon public-resources -s subscription-id

# Get GCP project information
nebula gcp recon projects-list
```

## Common Commands

**AWS Reconnaissance:**
```bash
# Account information and permissions
nebula aws recon account-auth-details
nebula aws recon whoami

# Resource discovery
nebula aws recon list-all-resources -r us-east-1
nebula aws recon public-resources -r all

# Security scanning
nebula aws recon find-secrets -t AWS::EC2::Instance
nebula aws recon find-secrets -t AWS::Lambda::Function
```

**Azure Reconnaissance:**
```bash
# Environment details
nebula azure recon summary -s subscription-id

# Resource enumeration  
nebula azure recon list-all-resources -s subscription-id
nebula azure recon public-resources -s all

# DevOps secrets scanning
nebula azure recon devops-secrets --organization org-name
```

**Analysis Modules:**
```bash
# AWS key analysis
nebula aws analyze access-key-to-account-id -k AKIA...
nebula aws analyze known-account -a 123456789012

# IP analysis
nebula aws analyze ip-lookup -i 1.2.3.4
```

## Output and Results

**Output Formats:**
- **Console**: Real-time progress and summaries
- **JSON**: Structured data in `nebula-output/` directory
- **Markdown**: Human-readable tables

**Common Flags:**
```bash
# Global options
--log-level string    Log level (debug, info, warn, error)
--output string       Output directory (default "nebula-output")
--quiet              Suppress user messages
--no-color           Disable colored output

# Provider-specific  
-r, --regions string  AWS regions ('all' or comma-separated)
-s, --subscription    Azure subscription ID
-t, --resource-type   Cloud resource type filter
```

## MCP Server

Nebula provides an MCP (Model Context Protocol) server for AI assistants:

**Stdio Server:**
```bash
nebula mcp-server
```

**HTTP Server:**
```bash
nebula mcp-server --http --addr :8080
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "nebula": {
      "command": "/path/to/nebula", 
      "args": ["mcp-server"]
    }
  }
}
```

## Security Notes

- **Permissions**: Ensure appropriate read-only permissions before scanning. Note: Many AWS modules use the [Cloud Control API](https://aws.amazon.com/cloudcontrolapi/) which requires `cloudformation:ListResources` and `cloudformation:GetResources`.
- **Scope Control**: Use resource type and region filters to limit scan scope

## Architecture

Nebula uses Praetorian's  [Janus Framework](https://github.com/praetorian-inc/janus-framework).
- **Links**: Individual processing units that can be chained together
- **Modules**: Pre-configured chains for specific security testing scenarios
- **Outputters**: Pluggable output processing for different formats
- **Registry**: Dynamic module discovery and CLI generation

For development details, see [DEVELOPMENT.md](DEVELOPMENT.md).