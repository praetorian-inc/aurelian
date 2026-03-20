<img width="2752" alt="Aurelian — Open-Source Multi-Cloud Security Reconnaissance Framework for AWS, Azure, and GCP" src="docs/aurelian.webp" />
<h1 align="center">Aurelian</h1>

<p align="center">
  <strong>Open-source cloud security reconnaissance framework</strong><br/>
  Detect secrets, misconfigurations, public exposure, and privilege escalation paths across AWS, Azure, and GCP — from a single CLI.
</p>

<p align="center">
<a href="https://github.com/praetorian-inc/aurelian/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/praetorian-inc/aurelian/ci.yml?style=flat-square&label=build" alt="Aurelian CI Build Status"></a>
<a href="https://github.com/praetorian-inc/aurelian/releases"><img src="https://img.shields.io/github/v/release/praetorian-inc/aurelian?style=flat-square" alt="Aurelian Latest Release"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="Apache 2.0 License"></a>
<a href="https://github.com/praetorian-inc/aurelian/stargazers"><img src="https://img.shields.io/github/stars/praetorian-inc/aurelian?style=flat-square" alt="GitHub Stars"></a>
<a href="https://goreportcard.com/report/github.com/praetorian-inc/aurelian"><img src="https://goreportcard.com/badge/github.com/praetorian-inc/aurelian?style=flat-square" alt="Go Report Card"></a>
</p>

<p align="center">
  <a href="#what-is-aurelian">What is Aurelian?</a> •
  <a href="#key-capabilities">Capabilities</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#modules">Modules</a> •
  <a href="#documentation">Docs</a> •
  <a href="#faq">FAQ</a>
</p>

---

## What is Aurelian?

Aurelian is an open-source, multi-cloud security reconnaissance framework built in Go. It provides a single, unified command-line interface for cloud security assessments across Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).

Where other tools require you to learn separate workflows per cloud provider, Aurelian gives you **one command structure that works everywhere**: `aurelian [platform] recon [module]`. Each module encapsulates a complex, multi-step security workflow — resource enumeration, content extraction, secrets scanning, policy analysis, access evaluation — behind a single command.

Aurelian was built by the offensive security team at [Praetorian](https://www.praetorian.com), based on years of cloud penetration testing and red team engagements across hundreds of enterprise environments.

### Why Aurelian?

| Challenge | How Aurelian Solves It |
|-----------|----------------------|
| **Fragmented tooling** — different tools per cloud, per task | Unified CLI: same commands, same output across AWS, Azure, and GCP |
| **Complex enumeration workflows** — dozens of API calls for a single finding | Each module orchestrates the full workflow behind one command |
| **Secrets scattered across cloud services** — user data, env vars, configs, logs | `find-secrets` extracts content from 30+ source types and scans with [Titus](https://github.com/praetorian-inc/titus) |
| **Detection during assessments** — CloudTrail logs reveal recon activity | OPSEC-aware techniques minimize logging footprint |
| **Understanding IAM blast radius** — permissions are complex and interconnected | Graph analysis with Neo4j visualizes privilege escalation paths |

---

## Key Capabilities

### Secrets Discovery

Enumerates cloud resources, extracts content from 30+ source types (EC2 user data, Lambda code, CloudFormation templates, CloudWatch logs, ECS task definitions, environment variables, storage blobs, application configurations), and scans with [Titus](https://github.com/praetorian-inc/titus) for hardcoded credentials, API keys, and tokens. Optional validation confirms whether discovered secrets are active.

### Public Resource Detection

Combines resource listing, property enrichment, policy fetching, and access evaluation to identify publicly accessible resources — open S3 buckets, exposed databases, public IPs, anonymous-access storage accounts, and more.

### IAM Privilege Escalation Analysis

Collects IAM data (Get Account Authorization Details, resource policies, org policies), evaluates effective permissions, and detects privilege escalation paths. Outputs JSON or populates a Neo4j graph database for interactive exploration.

### Subdomain Takeover Detection

Checks DNS records in Route53, Azure DNS, and Cloud DNS against known cloud-specific takeover patterns — dangling CNAMEs pointing to unclaimed cloud resources.

### Cloud Misconfiguration Scanning

Azure Resource Graph template-based detection for weak authentication, disabled RBAC, overly permissive access rules, and other configuration issues.

### OPSEC-Aware Reconnaissance

Covert techniques that avoid CloudTrail logging. The `whoami` module identifies the caller ARN using APIs that leak identity in error messages without generating audit log entries.

---

## Supported Cloud Platforms

| Platform | Alias | Modules | Capabilities |
|----------|-------|---------|--------------|
| **Amazon Web Services (AWS)** | `aws`, `amazon` | 12 | Secrets, public resources, IAM graph, subdomain takeover, OPSEC whoami, cost analysis, CDK/CloudFront takeover |
| **Microsoft Azure** | `azure`, `az` | 6 | Secrets, public resources, configuration scan, subdomain takeover, conditional access policies |
| **Google Cloud Platform (GCP)** | `gcp`, `google` | 4 | Secrets, public resources, subdomain takeover, resource enumeration |

---

## Installation

### From Source (Recommended)

```sh
git clone https://github.com/praetorian-inc/aurelian.git
cd aurelian
go build -o aurelian main.go
```

Requires **Go 1.24+**.

### Docker

```sh
docker build -t aurelian .
docker run --rm -v ~/.aws:/root/.aws aurelian aws recon whoami
```

A `docker-compose.yml` is included with credential volume mounts for all three cloud providers.

### Build Options

```sh
# Standard build
go build -o aurelian .

# SQLite-backed store (for memory-constrained environments)
go build -tags cache_sqlite -o aurelian .
```

---

## Quick Start

### Verify Your Identity (OPSEC-Safe)

```sh
# Identifies caller ARN without CloudTrail logging
aurelian aws recon whoami
```

### Find Hardcoded Secrets

```sh
# Scan all AWS regions for secrets in EC2 user data, Lambda code, CloudWatch logs, and more
aurelian aws recon find-secrets

# Scan Azure subscriptions
aurelian azure recon find-secrets --subscription-id <id>

# Scan GCP projects
aurelian gcp recon find-secrets --project-id <id>
```

### Detect Public Resources

```sh
# Find publicly accessible AWS resources (S3 buckets, RDS instances, etc.)
aurelian aws recon public-resources

# Azure public resources
aurelian azure recon public-resources --subscription-id <id>

# GCP public resources
aurelian gcp recon public-resources --project-id <id>
```

### Analyze IAM Privilege Escalation

```sh
# Build IAM graph and detect escalation paths
aurelian aws recon graph --neo4j-uri bolt://localhost:7687

# Offline analysis from GAAD export
aurelian aws analyze analyze-iam-permissions --gaad-file gaad.json
```

### Detect Subdomain Takeovers

```sh
aurelian aws   recon subdomain-takeover
aurelian azure recon subdomain-takeover --subscription-id <id>
aurelian gcp   recon subdomain-takeover --project-id <id>
```

### List All Modules

```sh
aurelian list-modules
```

---

## Modules

### AWS Reconnaissance

| Module | Description |
|--------|-------------|
| `find-secrets` | Enumerates resources, extracts content from 30+ source types, scans with Titus |
| `public-resources` | Detects publicly accessible resources through policy and property evaluation |
| `graph` | Collects IAM data, evaluates permissions, detects privilege escalation paths |
| `subdomain-takeover` | Checks Route53 DNS for dangling CNAME cloud takeover patterns |
| `whoami` | OPSEC-safe identity check via CloudTrail-silent API techniques |
| `list-all` | Enumerates all Cloud Control resources across regions |
| `account-auth-details` | Exports IAM Get Account Authorization Details (GAAD) |
| `resource-policies` | Extracts resource-based policies for analysis |
| `org-policies` | Fetches AWS Organizations SCPs and policies |
| `cost-summary` | Summarizes AWS cost and usage data |
| `cdk-bucket-takeover` | Detects orphaned CDK bootstrap buckets |
| `cloudfront-s3-takeover` | Detects CloudFront distributions pointing to unclaimed S3 origins |

### AWS Analysis

| Module | Description |
|--------|-------------|
| `analyze-iam-permissions` | Offline IAM analysis — privilege escalation, cross-account access, create-then-use patterns |
| `expand-actions` | Expands IAM wildcard actions to concrete permissions |
| `access-key-to-account-id` | Resolves AWS access key to account ID |
| `ip-lookup` | Identifies AWS IP ranges for a given IP address |
| `known-account` | Checks if an account ID belongs to known AWS service accounts |

### Azure Reconnaissance

| Module | Description |
|--------|-------------|
| `find-secrets` | Discovers secrets across Azure services — Key Vaults, App Settings, Cosmos DB, and more |
| `public-resources` | Detects publicly exposed Azure resources |
| `configuration-scan` | Resource Graph template-based misconfiguration detection |
| `subdomain-takeover` | Checks Azure DNS zones for dangling CNAMEs |
| `conditional-access-policies` | Enumerates Conditional Access policies for weaknesses |
| `list-all` | Enumerates all resources across subscriptions |

### GCP Reconnaissance

| Module | Description |
|--------|-------------|
| `find-secrets` | Discovers secrets in GCP services — metadata, environment variables, storage objects |
| `public-resources` | Identifies publicly accessible GCP resources |
| `subdomain-takeover` | Checks Cloud DNS for dangling CNAME records |
| `list-all` | Enumerates all resources across projects |

---

## Architecture

Aurelian is built on three core patterns:

- **Modules** — Entry points implementing `plugin.Module`. Registered via `init()`, auto-discovered, wired into the CLI. Each encapsulates a complete security workflow.
- **Pipelines** — `pipeline.P[T]` is a generic streaming primitive with backpressure. Modules chain pipeline stages to process resources concurrently.
- **Components** — Reusable building blocks in `pkg/<csp>/<component>/` with pipeline-compatible methods. Stateless processors wired into modules via `pipeline.Pipe`.

```
Module → Pipeline.Pipe(Lister) → Pipeline.Pipe(Enricher) → Pipeline.Pipe(Evaluator) → Output
```

Aurelian's plugin architecture means adding a new module is as simple as implementing the `plugin.Module` interface and calling `plugin.Register()` — the CLI, flags, and parameter binding are handled automatically.

---

## Library Usage

Import Aurelian modules directly into Go applications:

```go
import (
    "github.com/praetorian-inc/aurelian/pkg/plugin"
    _ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

mod, _ := plugin.Get("aws", "recon", "whoami")
results, err := mod.Run(cfg)
```

---

## Documentation

Detailed per-module documentation is available in the [`docs/`](docs/) directory:

| Section | Description |
|---------|-------------|
| [`docs/aurelian_aws_recon.md`](docs/aurelian_aws_recon.md) | AWS reconnaissance module reference |
| [`docs/aurelian_aws_analyze.md`](docs/aurelian_aws_analyze.md) | AWS analysis module reference |
| [`docs/aurelian_azure_recon.md`](docs/aurelian_azure_recon.md) | Azure reconnaissance module reference |
| [`docs/aurelian_gcp_recon.md`](docs/aurelian_gcp_recon.md) | GCP reconnaissance module reference |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Architecture deep dive, pipeline lifecycle, integration testing |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add modules, components, and submit PRs |

---

## How Aurelian Compares

Aurelian occupies a unique position in the cloud security tooling landscape — it is purpose-built for **offensive security reconnaissance** with a unified multi-cloud interface, where most alternatives focus on compliance scanning or single-cloud exploitation.

| Capability | Aurelian | Prowler | ScoutSuite | Pacu | Cartography |
|------------|----------|---------|------------|------|-------------|
| **Multi-cloud unified CLI** | AWS, Azure, GCP | AWS, Azure, GCP, K8s | AWS, Azure, GCP | AWS only | AWS, Azure, GCP |
| **Secrets discovery (30+ sources)** | Yes | Limited | No | No | No |
| **OPSEC-aware (CloudTrail evasion)** | Yes | No | No | Partial | No |
| **IAM privilege escalation graph** | Yes (Neo4j) | No | No | Yes | Yes (Neo4j) |
| **Subdomain takeover detection** | Yes | No | No | No | No |
| **Public resource detection** | Yes | Yes | Yes | No | No |
| **Misconfiguration scanning** | Yes (Azure) | Yes | Yes | No | No |
| **Compliance frameworks (CIS, NIST)** | No | Yes | Yes | No | No |
| **Written in** | Go | Python | Python | Python | Python |
| **Plugin architecture** | Yes | Yes | No | Yes | No |

**Choose Aurelian when** you need offensive reconnaissance across multiple clouds — secrets, exposure, IAM analysis, and takeover detection — with OPSEC awareness. **Choose Prowler/ScoutSuite** when you need compliance-focused posture management with CIS benchmark reporting.

---

## FAQ

### What cloud providers does Aurelian support?

Aurelian supports Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP). All three use the same command structure: `aurelian [platform] recon [module]`.

### What permissions does Aurelian need?

Aurelian uses read-only API access. For AWS, the `SecurityAudit` managed policy covers most modules. Azure modules need `Reader` role. GCP modules need `Viewer` role. The `whoami` module requires no permissions — it uses APIs that leak identity in error responses.

### Does Aurelian write to CloudTrail?

Most modules generate standard read-only CloudTrail entries. The `whoami` module specifically avoids CloudTrail logging by using covert API techniques (Timestream, Pinpoint, SQS error messages). Set `--opsec_level` to control logging behavior.

### How is Aurelian different from Prowler?

Prowler is a cloud security posture management (CSPM) tool focused on compliance frameworks like CIS Benchmarks and NIST. Aurelian is a reconnaissance framework built for offensive security — it finds secrets in 30+ cloud source types, detects IAM privilege escalation paths, identifies subdomain takeover opportunities, and uses OPSEC-aware techniques that minimize detection. They are complementary tools.

### How is Aurelian different from Pacu?

Pacu is an AWS exploitation framework for active attacks (privilege escalation, persistence, data exfiltration). Aurelian is a reconnaissance framework for finding weaknesses — it scans and reports but doesn't exploit. Aurelian also supports Azure and GCP, while Pacu is AWS-only.

### Can I use Aurelian as a Go library?

Yes. All modules are importable via `github.com/praetorian-inc/aurelian/pkg/plugin`. Call `plugin.Get()` to retrieve a module and `mod.Run()` to execute it programmatically.

### How do I add a new module?

Implement the `plugin.Module` interface and register with `plugin.Register()` in `init()`. The CLI, flags, and parameter binding are handled automatically. See [CONTRIBUTING.md](CONTRIBUTING.md) for a full walkthrough.

### What is Titus?

[Titus](https://github.com/praetorian-inc/titus) is Praetorian's open-source secrets detection engine. Aurelian's `find-secrets` modules extract content from cloud resources and pipe it through Titus for pattern-based scanning with optional secret validation.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines. Only run Aurelian against cloud environments you own or have explicit authorization to assess.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, module creation, and PR guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## About Praetorian

Aurelian is developed and maintained by [Praetorian](https://www.praetorian.com), an offensive security company that helps enterprises find and fix their most critical vulnerabilities. Our tools are built from real-world cloud penetration testing and red team engagements.

- [Praetorian Website](https://www.praetorian.com)
- [Praetorian GitHub](https://github.com/praetorian-inc)
- [Titus — Secrets Detection Engine](https://github.com/praetorian-inc/titus)
