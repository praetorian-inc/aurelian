<h1 align="center">
  Aurelian
  <br>
  <sub>Cloud Security Testing Framework</sub>
</h1>

<p align="center">
<a href="https://github.com/praetorian-inc/aurelian/releases"><img src="https://img.shields.io/github/v/release/praetorian-inc/aurelian?style=flat-square" alt="Release"></a>
<a href="https://github.com/praetorian-inc/aurelian/actions"><img src="https://img.shields.io/github/actions/workflow/status/praetorian-inc/aurelian/ci.yml?style=flat-square" alt="Build Status"></a>
<a href="https://goreportcard.com/report/github.com/praetorian-inc/aurelian"><img src="https://goreportcard.com/badge/github.com/praetorian-inc/aurelian?style=flat-square" alt="Go Report Card"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
<a href="https://github.com/praetorian-inc/aurelian/stargazers"><img src="https://img.shields.io/github/stars/praetorian-inc/aurelian?style=flat-square" alt="Stars"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#library-usage">Library</a> •
  <a href="#use-cases">Use Cases</a> •
  <a href="#troubleshooting">Troubleshooting</a>
</p>

> **Comprehensive cloud security testing framework written in Go.** Identify security misconfigurations, discover secrets, and analyze IAM policies across AWS, Azure, and GCP.

Aurelian performs reconnaissance and security analysis across multi-cloud environments. Use it during penetration tests to enumerate cloud resources, discover exposed assets, and identify privilege escalation paths.

## Features

- **50+ Security Modules** — Reconnaissance, secrets discovery, and policy analysis across AWS, Azure, GCP, and SaaS platforms
- **OPSEC-Aware Operations** — Covert techniques that minimize CloudTrail logging and detection footprint
- **Secrets Discovery** — Integrated Nosey Parker scanning for credentials across cloud storage, instances, and container images
- **Multi-Cloud Support** — AWS, Azure, GCP, and container registries with unified CLI interface
- **Flexible Output** — JSON, Markdown, CSV, SARIF, or human-readable formats
- **MCP Integration** — Model Context Protocol server for LLM-powered cloud security analysis
- **Go Library** — Import directly into your Go applications

## Installation

### From GitHub

```sh
go install github.com/praetorian-inc/aurelian@latest
```

### From Source

```sh
git clone https://github.com/praetorian-inc/aurelian.git
cd aurelian
go build -v -ldflags="-s -w" -o aurelian main.go
./aurelian -h
```

### Docker

```sh
git clone https://github.com/praetorian-inc/aurelian.git
cd aurelian
docker build -t aurelian .
docker run --rm aurelian -h
docker run --rm -v ~/.aws:/root/.aws aurelian aws recon whoami
```

## Quick Start

Identify the current AWS identity (OPSEC-safe):

```sh
aurelian aws recon whoami
# Account: 123456789012
# ARN: arn:aws:iam::123456789012:user/testuser
```

Find publicly accessible resources:

```sh
aurelian aws recon public-resources --output-format json
# {"type":"s3","name":"public-bucket","access":"public-read",...}
```

Scan for secrets in Azure storage:

```sh
aurelian azure recon find-secrets --subscription-id <id>
```

## Usage

```
aurelian [platform] [category] [module] [flags]

PLATFORMS:
  aws     Amazon Web Services
  azure   Microsoft Azure (alias: az)
  gcp     Google Cloud Platform (alias: google)
  saas    SaaS platforms (Docker registries)

CATEGORIES:
  recon     Reconnaissance and enumeration
  analyze   Analysis and intelligence
  secrets   Secrets discovery

EXAMPLES:
  aurelian aws recon whoami
  aurelian aws recon public-resources --output-format json
  aurelian azure recon find-secrets --subscription-id <id>
  aurelian gcp recon list-instances --project-id <id>
  aurelian list-modules
```

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--output-format` | Output format: default\|json\|markdown | default |
| `--output-file`, `-f` | Output file path | stdout |
| `--log-level` | Log level (debug, info, warn, error) | info |
| `--no-color` | Disable colored output | false |
| `--quiet` | Suppress banner and user messages | false |

### Examples

**List all available modules:**

```sh
aurelian list-modules
```

**AWS reconnaissance with JSON output:**

```sh
aurelian aws recon public-resources --output-format json -f results.json
```

**Analyze IAM access key:**

```sh
aurelian aws analyze access-key-to-account-id --access-key AKIAIOSFODNN7EXAMPLE
```

**Azure conditional access policy review:**

```sh
aurelian azure recon conditional-access-policies --tenant-id <id>
```

**GCP storage secrets scan:**

```sh
aurelian gcp secrets scan-storage --project-id <id>
```

## Modules

**50+ security modules** across AWS, Azure, GCP, and SaaS platforms:

### AWS (23 modules)

#### Recon

| Module | Description |
|--------|-------------|
| `whoami` | Covert identity discovery using OPSEC-safe API calls |
| `account-auth-details` | Account authentication configuration |
| `apollo` | Security group and infrastructure graph analysis |
| `apollo-offline` | Offline Apollo analysis from cached data |
| `cloudfront-s3-takeover` | Detect vulnerable CloudFront → S3 configurations |
| `cdk-bucket-takeover` | CDK-generated bucket takeover detection |
| `ecr-dump` | ECR repository enumeration and scanning |
| `public-resources` | Publicly accessible resource detection |
| `public-resources-single` | Single-resource public access check |
| `resource-policies` | Resource-based policy analysis |
| `get-console` | Generate AWS console sign-in URLs |
| `get-orgpolicies` | Organization policy enumeration |
| `find-secrets` | Secrets discovery across AWS resources |
| `find-secrets-resource` | Single-resource secrets scan |
| `ec2-screenshot-analysis` | EC2 instance screenshot capture and analysis |
| `list` | Resource enumeration by type |
| `list-all` | Complete account resource enumeration |
| `summary` | Account security posture summary |

#### Analyze

| Module | Description |
|--------|-------------|
| `access-key-to-account-id` | Derive account ID from access key |
| `apollo-query` | Advanced infrastructure graph queries |
| `expand-actions` | IAM action wildcard expansion |
| `ip-lookup` | IP address intelligence and attribution |
| `known-account` | Known AWS account identification |

### Azure (9 modules)

#### Recon

| Module | Description |
|--------|-------------|
| `public-resources` | Publicly accessible Azure resource detection |
| `arg-scan` | Azure Resource Graph template scanning |
| `conditional-access-policies` | Conditional access policy enumeration |
| `find-secrets` | Secrets discovery across Azure resources |
| `find-secrets-resource` | Single-resource secrets scan |
| `devops-secrets` | Azure DevOps secrets detection |
| `role-assignments` | RBAC role assignment enumeration |
| `list-all-resources` | Complete subscription resource listing |
| `summary` | Subscription security summary |

### GCP (17 modules)

#### Recon

| Module | Description |
|--------|-------------|
| `list-projects` | Project enumeration |
| `list-folders` | Folder hierarchy enumeration |
| `list-instances` | Compute instance enumeration |
| `list-storage` | Cloud Storage bucket enumeration |
| `list-cloud-run` | Cloud Run service enumeration |
| `list-functions` | Cloud Functions enumeration |
| `list-networking` | VPC and networking enumeration |
| `list-app-engine` | App Engine service enumeration |
| `list-artifactory` | Artifact Registry enumeration |

#### Compute

| Module | Description |
|--------|-------------|
| `instances` | Compute instance analysis |
| `networking` | Network configuration analysis |

#### Secrets

| Module | Description |
|--------|-------------|
| `scan-storage` | Cloud Storage secrets scan |
| `scan-instances` | Compute instance secrets scan |
| `scan-cloud-run` | Cloud Run secrets scan |
| `scan-functions` | Cloud Functions secrets scan |
| `scan-app-engine` | App Engine secrets scan |
| `scan-artifactory` | Artifact Registry secrets scan |

### SaaS (1 module)

| Module | Description |
|--------|-------------|
| `docker-dump` | Docker registry enumeration and image analysis |

## Library Usage

Import Aurelian into your Go applications:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/praetorian-inc/aurelian/pkg/plugin"
    // Import modules to register them
    _ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func main() {
    // Get a module from the registry
    mod, ok := plugin.Get("aws", "recon", "whoami")
    if !ok {
        log.Fatal("module not found")
    }

    // Configure and run
    cfg := plugin.Config{
        Args:    map[string]any{"action": "all"},
        Context: context.Background(),
    }

    results, err := mod.Run(cfg)
    if err != nil {
        log.Fatal(err)
    }

    for _, result := range results {
        fmt.Printf("%+v\n", result.Data)
    }
}
```

## MCP Server

Aurelian includes a Model Context Protocol server for LLM integration:

```sh
# Start MCP server (stdio transport)
aurelian mcp-server

# Start with HTTP/SSE transport
aurelian mcp-server --sse --port 8080
```

This exposes all modules as MCP tools, enabling AI assistants to perform cloud security analysis.

## Use Cases

### Penetration Testing

Enumerate cloud resources and identify attack vectors during authorized security assessments:

```sh
aurelian aws recon whoami
aurelian aws recon public-resources --output-format json | jq '.type'
```

### Cloud Security Audits

Analyze IAM policies and detect misconfigurations across multi-cloud environments:

```sh
aurelian aws recon resource-policies
aurelian azure recon conditional-access-policies
```

### Secrets Discovery

Find exposed credentials and sensitive data in cloud storage and compute resources:

```sh
aurelian aws recon find-secrets
aurelian gcp secrets scan-storage --project-id myproject
```

### Incident Response

Quickly enumerate resources and identify the blast radius during security incidents:

```sh
aurelian aws recon list-all --output-format json
aurelian aws recon summary
```

### Red Team Operations

OPSEC-aware reconnaissance that minimizes CloudTrail footprint:

```sh
aurelian aws recon whoami --action sns  # Uses SNS for covert identity check
```

## Architecture

```mermaid
graph LR
    A[CLI Input] --> B[Command Parser]
    B --> C[Plugin Registry]
    C --> D{Platform}
    D -->|AWS| E[AWS Modules]
    D -->|Azure| F[Azure Modules]
    D -->|GCP| G[GCP Modules]
    D -->|SaaS| H[SaaS Modules]
    E --> I[Cloud APIs]
    F --> I
    G --> I
    H --> I
    I --> J[Results]
    J --> K[Output Formatter]
    K --> L[JSON/Markdown/Console]
```

## Why Aurelian?

### vs ScoutSuite

- **OPSEC-aware**: Covert techniques that avoid CloudTrail logging where possible
- **Focused modules**: Run specific checks rather than full account enumeration
- **Secrets detection**: Integrated Nosey Parker for credential discovery

### vs Prowler

- **Multi-cloud unified CLI**: Same interface across AWS, Azure, and GCP
- **Library integration**: Import modules directly into Go applications
- **MCP support**: LLM integration for AI-assisted cloud security

### vs Manual CLI

- **Structured output**: Native JSON/Markdown for pipeline integration
- **Combined analysis**: Correlate findings across resources and services
- **Repeatable**: Consistent module execution for audit trails

## Troubleshooting

### Authentication errors

**Cause**: Missing or invalid cloud credentials.

**Solution**: Ensure credentials are configured:

```sh
# AWS
aws configure
# or
export AWS_PROFILE=myprofile

# Azure
az login

# GCP
gcloud auth application-default login
```

### Module not found

**Cause**: Incorrect module path or typo.

**Solution**: List available modules:

```sh
aurelian list-modules
```

### Permission denied

**Cause**: Insufficient IAM permissions for the operation.

**Solution**: Ensure the authenticated identity has required permissions. Check module documentation for specific requirements.

### Timeout errors

**Cause**: Slow API responses or large result sets.

**Solution**: Use more specific filters or increase timeout via context.

## Terminology

- **Module**: A security check or enumeration task targeting a specific cloud service
- **Platform**: Cloud provider (AWS, Azure, GCP) or SaaS service
- **Category**: Module grouping (recon, analyze, secrets)
- **OPSEC**: Operational Security — minimizing detection during assessments
- **Covert**: Techniques that avoid or minimize audit logging

## Support

If you find Aurelian useful, please consider giving it a star:

[![GitHub stars](https://img.shields.io/github/stars/praetorian-inc/aurelian?style=social)](https://github.com/praetorian-inc/aurelian)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgements

Aurelian is developed and maintained by [Praetorian](https://www.praetorian.com/).
