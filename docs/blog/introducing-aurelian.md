# Cloud Recon at Scale: Introducing Aurelian

**TL;DR:** Aurelian is an open-source cloud security testing framework written in Go. It ships 50+ modules across AWS, Azure, GCP, and SaaS platforms. It finds publicly accessible resources through actual policy evaluation, discovers hardcoded secrets in cloud compute and storage, maps IAM privilege escalation paths, and detects subdomain takeover conditions. It is OPSEC-aware, streams results through a memory-efficient pipeline, and works as a CLI, a Go library, or an MCP server for LLM integration. [Get it on GitHub.](https://github.com/praetorian-inc/aurelian)

---

## The Problem With Cloud Recon

Say you find yourself three days into a cloud penetration test. You have credentials for an AWS account, a handful of Azure subscriptions, and a GCP project that somebody mentioned in a Slack thread. Your job is to figure out what is exposed, what is misconfigured, and where the privilege escalation paths are.

You know the routine. You run `aws s3 ls` and start scrolling. You fire up a few open-source scanners, each with its own output format and its own assumptions about what "public" means. You pull IAM policies by hand and try to reason about wildcard actions in your head. Somewhere in the process, you switch to Azure, realize you need a completely different set of tools, and start the whole cycle over again.

This workflow is slow. It is error-prone. And it does not scale to the kinds of multi-cloud environments that most organizations actually run.

Aurelian exists to fix that.

## What Is Aurelian?

Aurelian is a comprehensive cloud security testing framework. It performs reconnaissance, secrets discovery, and policy analysis across AWS, Azure, and GCP from a single CLI. Every module follows the same interface, produces the same structured output types, and plugs into the same streaming pipeline architecture. You learn the tool once and use it everywhere.

```
aurelian [platform] [category] [module] [flags]

aurelian aws recon public-resources --output-format json
aurelian azure recon list-all --subscription-id <id>
aurelian gcp secrets scan-storage --project-id myproject
aurelian aws analyze analyze-iam-permissions --gaad-file gaad.json
```

The name continues Praetorian's tradition of Roman-themed security tooling alongside [Trajan](https://github.com/praetorian-inc/trajan) and [Titus](https://github.com/praetorian-inc/titus). Where Trajan targets CI/CD pipelines and Titus hunts for secrets in source code, Aurelian covers the cloud infrastructure layer.

## What It Does

### Public Resource Discovery Through Policy Evaluation

Most tools check a few boolean flags to determine whether a resource is publicly accessible. Aurelian takes a different approach. The `public-resources` module enumerates resources via the AWS Cloud Control API, enriches them with service-specific properties (RDS `PubliclyAccessible`, Cognito self-signup settings, Lambda function URL auth types), fetches their resource-based policies, and evaluates those policies against anonymous and cross-account access contexts using an actual IAM policy evaluation engine.

This is not a heuristic. It is the same evaluation logic that AWS uses internally, applied against every resource policy in the account. It considers condition keys, organization SCPs, and resource ARN patterns. Resources that allow public access get flagged as high severity. Resources with policies that are ambiguous or complex enough to require human judgment get flagged as medium and marked for triage.

```sh
aurelian aws recon public-resources --output-format json -f results.json
```

The module builds a pipeline that chains four stages together: listing, enrichment, policy fetching, and evaluation. Each stage streams results to the next through Go channels. The account never needs to fit in memory all at once.

### Secrets Discovery Across Cloud Resources

The `find-secrets` module takes a similar approach to the resources it scans. It enumerates cloud resources, extracts content likely to contain hardcoded credentials (EC2 user data, Lambda function code, CloudFormation templates, CloudWatch log events, ECS task definitions, SSM documents, Step Functions state machine definitions), and feeds that content into [Titus](https://github.com/praetorian-inc/titus) for scanning.

```sh
aurelian aws recon find-secrets
aurelian gcp secrets scan-storage --project-id myproject
aurelian azure recon find-secrets --subscription-id <id>
```

When Titus identifies a credential, Aurelian validates it with a live API call where possible. A confirmed-valid AWS key is a high-severity finding. An unvalidated match is medium. The proof data includes the full match context, provenance metadata (account ID, region, resource type, resource ARN), and validation status, so you can hand it directly to the client or feed it into a downstream reporting pipeline.

### IAM Privilege Escalation Analysis

The `account-auth-details` module pulls the full GetAccountAuthorizationDetails (GAAD) dataset: every user, role, group, and policy in the account. The companion `analyze-iam-permissions` module consumes that data and evaluates every principal's effective permissions to detect privilege escalation paths, cross-account access, and create-then-use attack patterns.

For environments where you want a visual representation, the `graph` module can export the full IAM relationship graph to Neo4j, where you can query it with Cypher to answer questions like "which roles can assume into this production account?" or "what is the shortest path from this developer role to admin?"

```sh
aurelian aws recon account-auth-details -f gaad.json
aurelian aws analyze analyze-iam-permissions --gaad-file gaad.json
aurelian aws recon graph --neo4j-uri bolt://localhost:7687
```

### Subdomain Takeover Detection

The `cloudfront-s3-takeover` module identifies CloudFront distributions whose S3 origins point to buckets that no longer exist or are owned by a different account. It cross-references Route53 records to determine whether DNS is actively routing traffic to the vulnerable distribution. A distribution with a missing bucket is medium severity. A distribution with active DNS pointing to it is high. A distribution whose origin bucket is owned by someone else is critical, because the takeover may have already happened.

```sh
aurelian aws recon cloudfront-s3-takeover
```

### Full Resource Enumeration

Sometimes you just want to know what is in the account. The `list-all` module enumerates every resource across all enabled regions using the AWS Cloud Control API. The Azure equivalent uses Azure Resource Graph for the same purpose. Both produce structured `AWSResource` or equivalent output types with resource IDs, ARNs, regions, properties, and URLs.

```sh
aurelian aws recon list-all --output-format json
aurelian azure recon list-all --subscription-id <id>
```

## How It Works

### The Plugin System

Every Aurelian module implements a single `Module` interface:

```go
type Module interface {
    ID() string
    Name() string
    Description() string
    Platform() Platform    // aws, azure, gcp, saas
    Category() Category    // recon, analyze, secrets
    Run(cfg Config, out *pipeline.P[model.AurelianModel]) error
    // ... metadata methods
}
```

Modules self-register via Go `init()` functions. The central plugin registry maps `platform/category/module-id` to implementations. The CLI is generated dynamically from the registry at startup: add a new module, recompile, and it appears in the command tree automatically. No boilerplate, no manual wiring.

### Streaming Pipelines

Aurelian processes results through a generic, channel-based pipeline. The core primitive is `P[T]`, a typed producer backed by an unbuffered Go channel. The `Pipe()` function connects stages:

```go
inputPipeline := pipeline.From(inputs...)
listed := pipeline.New[output.AWSResource]()
pipeline.Pipe(inputPipeline, lister.List, listed)

enriched := pipeline.New[output.AWSResource]()
pipeline.Pipe(listed, enricher.Enrich, enriched)

evaluated := pipeline.New[publicaccess.PublicAccessResult]()
pipeline.Pipe(enriched, evaluator.Evaluate, evaluated)
pipeline.Pipe(evaluated, riskFromResult, out)
```

Each stage runs in its own goroutine. Unbuffered channels provide natural backpressure, so a slow consumer automatically throttles a fast producer. Errors propagate through the chain and stop the entire pipeline. This design means Aurelian can scan an account with thousands of resources without loading them all into memory at once.

### Parameter Binding

Module parameters are defined as Go struct fields with struct tags:

```go
type FindSecretsConfig struct {
    plugin.AWSCommonRecon
    secrets.ScannerConfig
    MaxEvents  int `param:"max-events" desc:"Max log events per log group" default:"10000"`
    MaxStreams int `param:"max-streams" desc:"Max streams to sample per log group" default:"10"`
}
```

The framework uses reflection to generate CLI flags from these structs, bind user input to fields, run validation, and invoke `PostBind` hooks for credential initialization. Common configuration (AWS profile, regions, concurrency, caching) lives in shared base structs that modules compose via embedding. This keeps module code focused on the actual security logic.

### OPSEC Awareness

Every module declares an OPSEC level. Some operations are inherently noisy (enumerating all resources across all regions generates a lot of CloudTrail events). Others can be performed covertly using API calls that do not appear in audit logs. Aurelian makes this tradeoff explicit so operators can make informed decisions about detection risk.

## Getting Started

### Install

```sh
go install github.com/praetorian-inc/aurelian@latest
```

Or build from source:

```sh
git clone https://github.com/praetorian-inc/aurelian.git
cd aurelian
go build -v -ldflags="-s -w" -o aurelian main.go
```

Or use Docker:

```sh
docker build -t aurelian .
docker run --rm -v ~/.aws:/root/.aws aurelian aws recon public-resources
```

### Use as a Library

Every module is importable as a Go package. If you are building your own tooling and want to use Aurelian's policy evaluation, secrets scanning, or resource enumeration as building blocks, you can:

```go
import (
    "github.com/praetorian-inc/aurelian/pkg/plugin"
    _ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

mod, _ := plugin.Get("aws", "recon", "public-resources")
results, err := mod.Run(cfg)
```

### Output Formats

Aurelian supports JSON, Markdown, CSV, SARIF, and human-readable output. JSON output is designed for pipeline integration. SARIF output slots into existing vulnerability management workflows. Use `--output-format json -f results.json` on any module.

## FAQ

**What cloud providers are supported?**
AWS, Azure, GCP, and SaaS platforms (Docker registries). AWS has the deepest coverage today with 23 modules. Azure and GCP support continues to expand.

**How is this different from Prowler or ScoutSuite?**
Aurelian is built for penetration testers, not compliance auditors. It evaluates resource policies using actual IAM evaluation logic rather than checking configuration flags. It includes secrets discovery, privilege escalation analysis, and subdomain takeover detection. It is also OPSEC-aware and designed to minimize detection during authorized assessments.

**Does it require special IAM permissions?**
It uses whatever credentials you provide. More permissions means more coverage. At minimum, read-only access to the services you want to scan. The `list-all` module benefits from `cloudcontrol:ListResources` and `cloudcontrol:GetResource` permissions.

**Can I add custom modules?**
Yes. Implement the `Module` interface, register with `plugin.Register()` in an `init()` function, and import the package. The CLI and MCP server pick it up automatically.

**What is the MCP server?**
Aurelian exposes all modules as [Model Context Protocol](https://modelcontextprotocol.io/) tools. This lets LLM-powered assistants perform cloud security analysis by calling Aurelian modules directly. Start it with `aurelian mcp-server`.

## What is Next

We are actively expanding coverage across all three cloud providers, with GCP and Azure modules in various stages of development. On the AWS side, we are adding ECR container image scanning to the secrets pipeline and broadening the set of resource types supported by the public access evaluator.

If you find bugs or want to contribute modules, open an issue or pull request on [GitHub](https://github.com/praetorian-inc/aurelian). Aurelian is Apache 2.0 licensed.

---

Aurelian is available now at [github.com/praetorian-inc/aurelian](https://github.com/praetorian-inc/aurelian).
