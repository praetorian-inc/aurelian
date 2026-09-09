<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# aurelian CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:3a3df07d804d8610b437eae54f3758618fe475e9ebbbe650cf1ae62b535be463`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`aurelian`](#aurelian) | *(none)* | Aurelian - Cloud Security Testing Framework |
| [`aurelian aws`](#aurelian-aws) | `amazon` | aws platform commands |
| [`aurelian aws analyze`](#aurelian-aws-analyze) | *(none)* | analyze commands for aws |
| [`aurelian aws analyze access-key-to-account-id`](#aurelian-aws-analyze-access-key-to-account-id) | *(none)* | Derives the AWS account ID from an access key ID using base32 decoding without making any API calls. |
| [`aurelian aws analyze analyze-iam-permissions`](#aurelian-aws-analyze-analyze-iam-permissions) | *(none)* | Analyzes IAM permissions from GAAD data to detect privilege escalation paths, cross-account access, and create-then-use attack patterns. Requires GAAD JSON file from account-auth-details module. |
| [`aurelian aws analyze expand-actions`](#aurelian-aws-analyze-expand-actions) | *(none)* | Expands wildcard IAM action patterns (e.g. s3:Get* or *) into the full list of matching AWS actions by fetching the AWS Policy Generator service map. |
| [`aurelian aws analyze graph`](#aurelian-aws-analyze-graph) | *(none)* | Analyzes a Neo4j graph populated by `aws recon graph --neo4j-uri` and surfaces privilege-escalation paths (non-admin principal → admin target) as risk findings. Requires --neo4j-uri pointing at the seeded graph. |
| [`aurelian aws analyze ip-lookup`](#aurelian-aws-analyze-ip-lookup) | *(none)* | Looks up an IP address against the AWS published IP ranges to determine whether it belongs to AWS, and if so, which service, region, and network border group. |
| [`aurelian aws analyze known-account`](#aurelian-aws-analyze-known-account) | *(none)* | Looks up an AWS account ID against known public account databases to identify the owning organization. |
| [`aurelian aws recon`](#aurelian-aws-recon) | *(none)* | recon commands for aws |
| [`aurelian aws recon account-auth-details`](#aurelian-aws-recon-account-auth-details) | *(none)* | Retrieves IAM account authorization details including users, roles, groups, and policies. Supports multiple profiles for multi-account collection. IAM is a global service, so this module always queries us-east-1 region. |
| [`aurelian aws recon cdk-bucket-takeover`](#aurelian-aws-recon-cdk-bucket-takeover) | *(none)* | Detects AWS CDK S3 bucket takeover vulnerabilities by identifying missing CDK staging buckets and insecure IAM policies. Scans for CDK bootstrap roles and validates associated S3 buckets for potential account takeover risks. |
| [`aurelian aws recon cloudfront-s3-takeover`](#aurelian-aws-recon-cloudfront-s3-takeover) | *(none)* | Detects CloudFront distributions with S3 origins pointing to non-existent buckets, which could allow attackers to take over the domain by creating the missing bucket. Also identifies Route53 records pointing to vulnerable distributions. |
| [`aurelian aws recon configuration-scan`](#aurelian-aws-recon-configuration-scan) | *(none)* | Evaluates AWS resource configuration posture and emits risks. Enumerates supported resource types once, enriches them, and runs typed checks (currently: EC2 IMDSv1 enabled). |
| [`aurelian aws recon cost-summary`](#aurelian-aws-recon-cost-summary) | *(none)* | Use Cost Explorer to summarize the services and regions in use, displaying costs in a markdown table. |
| [`aurelian aws recon find-secrets`](#aurelian-aws-recon-find-secrets) | *(none)* | Enumerates AWS resources via Cloud Control, extracts content likely to contain hardcoded secrets (EC2 user data, Lambda code, CloudFormation templates, CloudWatch logs, ECS task definitions, SSM documents and Parameter Store parameters, Step Functions executions), and scans with Titus. |
| [`aurelian aws recon get-console`](#aurelian-aws-recon-get-console) | *(none)* | Generates a federated AWS Console sign-in URL using STS credentials. Supports three credential paths: existing assumed-role session, role assumption via AssumeRole, and federation token via GetFederationToken. |
| [`aurelian aws recon graph`](#aurelian-aws-recon-graph) | *(none)* | Collects AWS IAM data (GAAD, resources, policies), evaluates permissions, and detects privilege escalation paths. Outputs JSON by default; use --neo4j-uri to populate graph database with relationships. |
| [`aurelian aws recon iam-quick-analyze`](#aurelian-aws-recon-iam-quick-analyze) | *(none)* | Quick IAM analysis: collects GAAD from one or more AWS profiles, scans for privilege escalation paths and trust relationship issues. Faster than the full graph module — no resource enumeration or Neo4j required. |
| [`aurelian aws recon list-all`](#aurelian-aws-recon-list-all) | *(none)* | List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services. Can scan multiple regions concurrently. |
| [`aurelian aws recon org-policies`](#aurelian-aws-recon-org-policies) | *(none)* | Collects AWS Organizations service control policies (SCPs) and resource control policies (RCPs), including the organizational hierarchy and policy-to-target mappings. |
| [`aurelian aws recon public-resources`](#aurelian-aws-recon-public-resources) | *(none)* | Finds publicly accessible AWS resources through policy evaluation, property inspection, and enrichment. Combines resource listing, enrichment, policy fetching, and public access evaluation to identify resources that are exposed to the internet or allow anonymous access. |
| [`aurelian aws recon regions`](#aurelian-aws-recon-regions) | *(none)* | Lists the AWS regions enabled for the account, reporting whether the list came from the Account API, the EC2 API, or the compiled-in fallback list. |
| [`aurelian aws recon resource-policies`](#aurelian-aws-recon-resource-policies) | *(none)* | Retrieves resource-based policies for AWS resources that support them (S3 buckets, Lambda functions, SNS topics, SQS queues, EFS file systems, OpenSearch/Elasticsearch domains). Policies are added to the ResourcePolicy property of each resource. |
| [`aurelian aws recon subdomain-takeover`](#aurelian-aws-recon-subdomain-takeover) | *(none)* | Detects dangling DNS records in Route53 that are vulnerable to subdomain takeover. Enumerates all records from public hosted zones and checks for: Elastic Beanstalk CNAME hijacking, dangling Elastic IP A records, and orphaned NS delegations. |
| [`aurelian aws recon whoami`](#aurelian-aws-recon-whoami) | *(none)* | Covert whoami using AWS APIs that leak the caller ARN in error messages without logging to CloudTrail. Supports timestream, pinpoint, and sqs techniques. |
| [`aurelian azure`](#aurelian-azure) | `az` | azure platform commands |
| [`aurelian azure recon`](#aurelian-azure-recon) | *(none)* | recon commands for azure |
| [`aurelian azure recon apim-audit`](#aurelian-azure-recon-apim-audit) | *(none)* | Audits Azure API Management services for security weaknesses across two checks: (1) APIs (including MCP servers) with no authentication controls at the service, product, or API scope — inspects policy XML for validate-jwt, validate-azure-ad-token, ip-filter, and check-header elements, and confirms whether a subscription is required; (2) backends configured behind APIM that are reachable without traversing the gateway — Azure App Service backends are checked for publicNetworkAccess and IP restrictions, non-Azure backends (OpenShift, GCP Cloud Run, internal hosts) are flagged for manual triage. |
| [`aurelian azure recon apim-cross-tenant`](#aurelian-azure-recon-apim-cross-tenant) | *(none)* | Enumerates Azure APIM developer portal resources (APIs, products, delegation settings) without authentication, then optionally performs a cross-tenant captcha relay attack to create an account on the target portal and enumerate authenticated resources and subscription keys. |
| [`aurelian azure recon conditional-access-policies`](#aurelian-azure-recon-conditional-access-policies) | *(none)* | Enumerates Azure AD Conditional Access Policies via the Microsoft Graph API |
| [`aurelian azure recon configuration-scan`](#aurelian-azure-recon-configuration-scan) | *(none)* | Detects Azure configuration issues including weak authentication, disabled RBAC, privilege escalation paths, and overly permissive access rules via Azure Resource Graph. |
| [`aurelian azure recon find-secrets`](#aurelian-azure-recon-find-secrets) | *(none)* | Enumerates Azure resources via Resource Graph, extracts content likely to contain hardcoded secrets (VM user data, web app settings, automation variables, storage blobs, container env vars, Cosmos DB, APIM named values, Key Vault, and 30+ other sources), and scans with Titus. |
| [`aurelian azure recon list-all`](#aurelian-azure-recon-list-all) | *(none)* | List all Azure resources across subscriptions using Azure Resource Graph. Supports scanning specific subscriptions or all accessible subscriptions. |
| [`aurelian azure recon public-resources`](#aurelian-azure-recon-public-resources) | *(none)* | Identifies publicly accessible Azure resources by executing Azure Resource Graph query templates against target subscriptions. Detects public storage accounts, databases, key vaults, web apps, and other resources exposed to the internet. |
| [`aurelian azure recon subdomain-takeover`](#aurelian-azure-recon-subdomain-takeover) | *(none)* | Scan for dangling DNS records in Azure DNS zones that could enable subdomain takeover. Checks CNAME records for unclaimed App Service, Blob Storage, CDN, and Traffic Manager names; A/AAAA records for orphaned public IPs; and NS delegations to non-existent Azure DNS zones. |
| [`aurelian gcp`](#aurelian-gcp) | `google` | gcp platform commands |
| [`aurelian gcp recon`](#aurelian-gcp-recon) | *(none)* | recon commands for gcp |
| [`aurelian gcp recon find-secrets`](#aurelian-gcp-recon-find-secrets) | *(none)* | Enumerates GCP resources via project hierarchy, extracts content likely to contain hardcoded secrets (Compute metadata/startup scripts, Cloud Functions source, Cloud Run environment variables, App Engine environment variables), and scans with Titus. |
| [`aurelian gcp recon list-all`](#aurelian-gcp-recon-list-all) | *(none)* | List GCP resources across organization, folder, or project scope. Supports filtering by resource type and evaluates public/anonymous access. |
| [`aurelian gcp recon public-resources`](#aurelian-gcp-recon-public-resources) | *(none)* | List GCP resources with public network exposure or anonymous access. Focuses on resource types with meaningful public access indicators. |
| [`aurelian gcp recon subdomain-takeover`](#aurelian-gcp-recon-subdomain-takeover) | *(none)* | Scan for dangling DNS records in Cloud DNS that could enable subdomain takeover. Checks CNAME records for non-existent Cloud Storage buckets, Cloud Run services, and App Engine apps; A/AAAA records for orphaned IPs; and NS delegations to unclaimed Cloud DNS zones. |
| [`aurelian gendoc`](#aurelian-gendoc) | *(none)* | Generate Markdown documentation |
| [`aurelian list-modules`](#aurelian-list-modules) | *(none)* | Display available Aurelian modules in a tree structure |
| [`aurelian version`](#aurelian-version) | *(none)* | Print the version number of Aurelian |

## `aurelian`

Aurelian - Cloud Security Testing Framework

- Usage: `aurelian`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws`

aws platform commands

- Usage: `aurelian aws`
- Aliases: `amazon`
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze`

analyze commands for aws

- Usage: `aurelian aws analyze`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze access-key-to-account-id`

Derives the AWS account ID from an access key ID using base32 decoding without making any API calls.

- Usage: `aurelian aws analyze access-key-to-account-id`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--access-key-id` | `-k` | string |  | AWS access key ID (AKIA... or ASIA...) (required) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze analyze-iam-permissions`

Analyzes IAM permissions from GAAD data to detect privilege escalation paths, cross-account access, and create-then-use attack patterns. Requires GAAD JSON file from account-auth-details module.

- Usage: `aurelian aws analyze analyze-iam-permissions`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--gaad-file` |  | string |  | Path to GAAD JSON file (from account-auth-details module) (required) |
| `--org-policies-file` |  | string |  | Path to Org Policies JSON file (from org-policies module) |
| `--resource-policies-file` |  | string |  | Path to Resource Policies JSON file |
| `--resources-file` |  | string |  | Path to Resources JSON file (from list-all module) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze expand-actions`

Expands wildcard IAM action patterns (e.g. s3:Get* or *) into the full list of matching AWS actions by fetching the AWS Policy Generator service map.

- Usage: `aurelian aws analyze expand-actions`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--action` |  | string |  | IAM action pattern to expand (supports wildcards, e.g. s3:Get* or *) (required) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze graph`

Analyzes a Neo4j graph populated by `aws recon graph --neo4j-uri` and surfaces privilege-escalation paths (non-admin principal → admin target) as risk findings. Requires --neo4j-uri pointing at the seeded graph.

- Usage: `aurelian aws analyze graph`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--neo4j-password` |  | string | `neo4j` | Neo4j password |
| `--neo4j-uri` |  | string |  | Neo4j connection URI (e.g., bolt://localhost:7687) |
| `--neo4j-username` |  | string | `neo4j` | Neo4j username |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze ip-lookup`

Looks up an IP address against the AWS published IP ranges to determine whether it belongs to AWS, and if so, which service, region, and network border group.

- Usage: `aurelian aws analyze ip-lookup`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--ip` |  | string |  | IP address to look up in AWS IP ranges (required) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws analyze known-account`

Looks up an AWS account ID against known public account databases to identify the owning organization.

- Usage: `aurelian aws analyze known-account`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--account-id` |  | string |  | AWS account ID to look up (required) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon`

recon commands for aws

- Usage: `aurelian aws recon`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon account-auth-details`

Retrieves IAM account authorization details including users, roles, groups, and policies. Supports multiple profiles for multi-account collection. IAM is a global service, so this module always queries us-east-1 region.

- Usage: `aurelian aws recon account-auth-details`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` |  | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--profiles` | `-p` | stringSlice | `[]` | AWS profiles to collect (comma-separated) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon cdk-bucket-takeover`

Detects AWS CDK S3 bucket takeover vulnerabilities by identifying missing CDK staging buckets and insecure IAM policies. Scans for CDK bootstrap roles and validates associated S3 buckets for potential account takeover risks.

- Usage: `aurelian aws recon cdk-bucket-takeover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--cdk-qualifiers` | `-q` | stringSlice | `[hnb659fds]` | CDK bootstrap qualifiers to check |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon cloudfront-s3-takeover`

Detects CloudFront distributions with S3 origins pointing to non-existent buckets, which could allow attackers to take over the domain by creating the missing bucket. Also identifies Route53 records pointing to vulnerable distributions.

- Usage: `aurelian aws recon cloudfront-s3-takeover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon configuration-scan`

Evaluates AWS resource configuration posture and emits risks. Enumerates supported resource types once, enriches them, and runs typed checks (currently: EC2 IMDSv1 enabled).

- Usage: `aurelian aws recon configuration-scan`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon cost-summary`

Use Cost Explorer to summarize the services and regions in use, displaying costs in a markdown table.

- Usage: `aurelian aws recon cost-summary`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--days` | `-d` | int | `30` | Number of days to look back for cost data |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon find-secrets`

Enumerates AWS resources via Cloud Control, extracts content likely to contain hardcoded secrets (EC2 user data, Lambda code, CloudFormation templates, CloudWatch logs, ECS task definitions, SSM documents and Parameter Store parameters, Step Functions executions), and scans with Titus.

- Usage: `aurelian aws recon find-secrets`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--db-path` |  | string |  | Path for Titus SQLite database |
| `--disabled-titus-rules` |  | stringSlice | `[]` | Rule IDs to exclude from scanning |
| `--ignore-file` |  | string |  | Path to gitignore-style file for skipping paths; when empty uses a default list |
| `--max-events` |  | int | `10000` | Max log events per log group |
| `--max-streams` |  | int | `10` | Max streams to sample per log group |
| `--modified-since` |  | string |  | RFC3339 timestamp of the last successful scan; unchanged resources with reliable AWS modification metadata are skipped |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |
| `--ruleset` |  | string | `default` | Titus ruleset to apply; empty string disables ruleset filtering |
| `--validate` |  | bool | `false` | Validate detected secrets against their source APIs |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon get-console`

Generates a federated AWS Console sign-in URL using STS credentials. Supports three credential paths: existing assumed-role session, role assumption via AssumeRole, and federation token via GetFederationToken.

- Usage: `aurelian aws recon get-console`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--duration` |  | int | `3600` | Session duration in seconds (900-129600) |
| `--federation-name` |  | string | `aurelian-console` | Name for federation token request |
| `--mfa-token` |  | string |  | MFA token code for role assumption |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--role-arn` |  | string |  | IAM role ARN to assume before generating console URL |
| `--role-session-name` |  | string | `aurelian-console` | Session name for assumed role |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon graph`

Collects AWS IAM data (GAAD, resources, policies), evaluates permissions, and detects privilege escalation paths. Outputs JSON by default; use --neo4j-uri to populate graph database with relationships.

- Usage: `aurelian aws recon graph`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--neo4j-password` |  | string | `neo4j` | Neo4j password |
| `--neo4j-uri` |  | string |  | Neo4j connection URI (e.g., bolt://localhost:7687) |
| `--neo4j-username` |  | string | `neo4j` | Neo4j username |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--org-policies-file` |  | string |  | Path to Org Policies JSON file |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon iam-quick-analyze`

Quick IAM analysis: collects GAAD from one or more AWS profiles, scans for privilege escalation paths and trust relationship issues. Faster than the full graph module — no resource enumeration or Neo4j required.

- Usage: `aurelian aws recon iam-quick-analyze`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--gaad-dir` | `-D` | string |  | Directory of pre-collected GAAD JSON files (skips live collection) |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--profiles` | `-p` | stringSlice | `[]` | AWS profiles to analyze (comma-separated) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon list-all`

List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services. Can scan multiple regions concurrently.

- Usage: `aurelian aws recon list-all`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |
| `--scan-type` | `-s` | string | `full` | Scan type - 'full' for all resources or 'summary' for key services |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon org-policies`

Collects AWS Organizations service control policies (SCPs) and resource control policies (RCPs), including the organizational hierarchy and policy-to-target mappings.

- Usage: `aurelian aws recon org-policies`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon public-resources`

Finds publicly accessible AWS resources through policy evaluation, property inspection, and enrichment. Combines resource listing, enrichment, policy fetching, and public access evaluation to identify resources that are exposed to the internet or allow anonymous access.

- Usage: `aurelian aws recon public-resources`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--org-policies-file` |  | string |  | Path to Org Policies JSON file |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon regions`

Lists the AWS regions enabled for the account, reporting whether the list came from the Account API, the EC2 API, or the compiled-in fallback list.

- Usage: `aurelian aws recon regions`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon resource-policies`

Retrieves resource-based policies for AWS resources that support them (S3 buckets, Lambda functions, SNS topics, SQS queues, EFS file systems, OpenSearch/Elasticsearch domains). Policies are added to the ResourcePolicy property of each resource.

- Usage: `aurelian aws recon resource-policies`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon subdomain-takeover`

Detects dangling DNS records in Route53 that are vulnerable to subdomain takeover. Enumerates all records from public hosted zones and checks for: Elastic Beanstalk CNAME hijacking, dangling Elastic IP A records, and orphaned NS delegations.

- Usage: `aurelian aws recon subdomain-takeover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |
| `--regions` | `-r` | stringSlice | `[all]` | AWS regions to scan |
| `--resource-arn` | `-a` | stringSlice | `[]` | AWS target resource ARN |
| `--resource-type` | `-t` | stringSlice | `[all]` | AWS Cloud Control resource type |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian aws recon whoami`

Covert whoami using AWS APIs that leak the caller ARN in error messages without logging to CloudTrail. Supports timestream, pinpoint, and sqs techniques.

- Usage: `aurelian aws recon whoami`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--action` |  | string | `all` | Whoami technique: timestream, pinpoint, sqs, or all |
| `--opsec_level` |  | string | `none` | Operational security level for AWS operations |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--profile` | `-p` | string |  | AWS profile to use |
| `--profile-dir` |  | string |  | Set to override the default AWS profile directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure`

azure platform commands

- Usage: `aurelian azure`
- Aliases: `az`
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon`

recon commands for azure

- Usage: `aurelian azure recon`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon apim-audit`

Audits Azure API Management services for security weaknesses across two checks: (1) APIs (including MCP servers) with no authentication controls at the service, product, or API scope — inspects policy XML for validate-jwt, validate-azure-ad-token, ip-filter, and check-header elements, and confirms whether a subscription is required; (2) backends configured behind APIM that are reachable without traversing the gateway — Azure App Service backends are checked for publicNetworkAccess and IP restrictions, non-Azure backends (OpenShift, GCP Cloud Run, internal hosts) are flagged for manual triage.

- Usage: `aurelian azure recon apim-audit`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon apim-cross-tenant`

Enumerates Azure APIM developer portal resources (APIs, products, delegation settings) without authentication, then optionally performs a cross-tenant captcha relay attack to create an account on the target portal and enumerate authenticated resources and subscription keys.

- Usage: `aurelian azure recon apim-cross-tenant`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--attacker` |  | string |  | Attacker-controlled APIM portal URL (required for bypass mode) |
| `--email` |  | string |  | Account email (required for authenticated and bypass modes) |
| `--first` |  | string | `Test` | First name for registration (bypass mode) |
| `--insecure` | `-k` | bool | `false` | Skip TLS certificate verification |
| `--last` |  | string | `User` | Last name for registration (bypass mode) |
| `--mode` |  | string | `passive` | Scan mode: passive (unauthenticated enum only), authenticated (login + enum), bypass (cross-tenant captcha relay + signup + enum) |
| `--openai-key` |  | string |  | OpenAI API key for audio captcha transcription (bypass mode); falls back to OPENAI_API_KEY env var if unset |
| `--password` |  | string |  | Account password (required for authenticated and bypass modes) |
| `--target` |  | string |  | Target APIM developer portal URL (required) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon conditional-access-policies`

Enumerates Azure AD Conditional Access Policies via the Microsoft Graph API

- Usage: `aurelian azure recon conditional-access-policies`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon configuration-scan`

Detects Azure configuration issues including weak authentication, disabled RBAC, privilege escalation paths, and overly permissive access rules via Azure Resource Graph.

- Usage: `aurelian azure recon configuration-scan`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--enricher-timeout` |  | int | `120` | Per-resource enricher timeout in seconds |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |
| `--template-dir` |  | string |  | Optional directory with additional YAML query templates |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon find-secrets`

Enumerates Azure resources via Resource Graph, extracts content likely to contain hardcoded secrets (VM user data, web app settings, automation variables, storage blobs, container env vars, Cosmos DB, APIM named values, Key Vault, and 30+ other sources), and scans with Titus.

- Usage: `aurelian azure recon find-secrets`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--db-path` |  | string |  | Path for Titus SQLite database |
| `--disabled-titus-rules` |  | stringSlice | `[]` | Rule IDs to exclude from scanning |
| `--ignore-file` |  | string |  | Path to gitignore-style file for skipping paths; when empty uses a default list |
| `--max-cosmos-doc-scan` |  | int | `50` | Max total Cosmos documents to scan per container |
| `--max-cosmos-doc-size` |  | int | `1048576` | Max individual Cosmos document size in bytes |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--resource-id` | `-i` | stringSlice | `[]` | Azure resource ID(s) to scan directly, skipping enumeration |
| `--ruleset` |  | string | `default` | Titus ruleset to apply; empty string disables ruleset filtering |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |
| `--validate` |  | bool | `false` | Validate detected secrets against their source APIs |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon list-all`

List all Azure resources across subscriptions using Azure Resource Graph. Supports scanning specific subscriptions or all accessible subscriptions.

- Usage: `aurelian azure recon list-all`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon public-resources`

Identifies publicly accessible Azure resources by executing Azure Resource Graph query templates against target subscriptions. Detects public storage accounts, databases, key vaults, web apps, and other resources exposed to the internet.

- Usage: `aurelian azure recon public-resources`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |
| `--template-dir` |  | string |  | Optional directory with additional YAML query templates |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian azure recon subdomain-takeover`

Scan for dangling DNS records in Azure DNS zones that could enable subdomain takeover. Checks CNAME records for unclaimed App Service, Blob Storage, CDN, and Traffic Manager names; A/AAAA records for orphaned public IPs; and NS delegations to non-existent Azure DNS zones.

- Usage: `aurelian azure recon subdomain-takeover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Maximum concurrent API requests |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--subscription-ids` | `-s` | stringSlice | `[all]` | Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp`

gcp platform commands

- Usage: `aurelian gcp`
- Aliases: `google`
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp recon`

recon commands for gcp

- Usage: `aurelian gcp recon`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp recon find-secrets`

Enumerates GCP resources via project hierarchy, extracts content likely to contain hardcoded secrets (Compute metadata/startup scripts, Cloud Functions source, Cloud Run environment variables, App Engine environment variables), and scans with Titus.

- Usage: `aurelian gcp recon find-secrets`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Max concurrent API requests |
| `--creds-file` | `-c` | string |  | Path to GCP credentials JSON |
| `--db-path` |  | string |  | Path for Titus SQLite database |
| `--disabled-titus-rules` |  | stringSlice | `[]` | Rule IDs to exclude from scanning |
| `--folder-id` |  | stringSlice | `[]` | GCP folder IDs |
| `--ignore-file` |  | string |  | Path to gitignore-style file for skipping paths; when empty uses a default list |
| `--include-sys-projects` |  | bool | `false` | Include system projects |
| `--org-id` | `-o` | stringSlice | `[]` | GCP organization IDs |
| `--output-dir` |  | string | `aurelian-output` | Base output directory |
| `--project-id` | `-p` | stringSlice | `[]` | GCP project IDs |
| `--resource-id` | `-i` | stringSlice | `[]` | GCP resource ID(s) to scan directly |
| `--resource-type` | `-t` | stringSlice | `[all]` | Resource types to enumerate |
| `--ruleset` |  | string | `default` | Titus ruleset to apply; empty string disables ruleset filtering |
| `--validate` |  | bool | `false` | Validate detected secrets against their source APIs |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp recon list-all`

List GCP resources across organization, folder, or project scope. Supports filtering by resource type and evaluates public/anonymous access.

- Usage: `aurelian gcp recon list-all`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Max concurrent API requests |
| `--creds-file` | `-c` | string |  | Path to GCP credentials JSON |
| `--folder-id` |  | stringSlice | `[]` | GCP folder IDs |
| `--include-sys-projects` |  | bool | `false` | Include system projects |
| `--org-id` | `-o` | stringSlice | `[]` | GCP organization IDs |
| `--project-id` | `-p` | stringSlice | `[]` | GCP project IDs |
| `--resource-id` | `-i` | stringSlice | `[]` | GCP resource ID(s) to scan directly |
| `--resource-type` | `-t` | stringSlice | `[all]` | Resource types to enumerate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp recon public-resources`

List GCP resources with public network exposure or anonymous access. Focuses on resource types with meaningful public access indicators.

- Usage: `aurelian gcp recon public-resources`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Max concurrent API requests |
| `--creds-file` | `-c` | string |  | Path to GCP credentials JSON |
| `--folder-id` |  | stringSlice | `[]` | GCP folder IDs |
| `--include-sys-projects` |  | bool | `false` | Include system projects |
| `--org-id` | `-o` | stringSlice | `[]` | GCP organization IDs |
| `--project-id` | `-p` | stringSlice | `[]` | GCP project IDs |
| `--resource-id` | `-i` | stringSlice | `[]` | GCP resource ID(s) to scan directly |
| `--resource-type` | `-t` | stringSlice | `[all]` | Resource types to enumerate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gcp recon subdomain-takeover`

Scan for dangling DNS records in Cloud DNS that could enable subdomain takeover. Checks CNAME records for non-existent Cloud Storage buckets, Cloud Run services, and App Engine apps; A/AAAA records for orphaned IPs; and NS delegations to unclaimed Cloud DNS zones.

- Usage: `aurelian gcp recon subdomain-takeover`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `5` | Max concurrent API requests |
| `--creds-file` | `-c` | string |  | Path to GCP credentials JSON |
| `--folder-id` |  | stringSlice | `[]` | GCP folder IDs |
| `--include-sys-projects` |  | bool | `false` | Include system projects |
| `--org-id` | `-o` | stringSlice | `[]` | GCP organization IDs |
| `--project-id` | `-p` | stringSlice | `[]` | GCP project IDs |
| `--resource-id` | `-i` | stringSlice | `[]` | GCP resource ID(s) to scan directly |
| `--resource-type` | `-t` | stringSlice | `[all]` | Resource types to enumerate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian gendoc`

Generate Markdown documentation

- Usage: `aurelian gendoc`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian list-modules`

Display available Aurelian modules in a tree structure

- Usage: `aurelian list-modules`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |

## `aurelian version`

Print the version number of Aurelian

- Usage: `aurelian version`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-color` |  | bool | `false` | Disable colored output |
| `--output-dir` |  | string | `aurelian-output` | Output directory (default: aurelian-output) |
| `--output-file` | `-f` | string |  | Output file path (overrides --output-dir) |
| `--quiet` |  | bool | `false` | Suppress user messages (overrides default verbose CLI mode) |
