# Enrichment Queries

This directory contains YAML-formatted Cypher queries that enrich the IAM graph with additional metadata and relationships after the initial transformation phase.

## Directory Structure

```
enrich/
└── aws/
    ├── accounts.yaml                              # Order 0: Account metadata
    ├── resource_to_role.yaml                      # Order 1: EC2/Lambda → Role links
    ├── extract_role_trust_relationships.yaml      # Order 2: Principal trust extraction
    ├── extract_role_trusted_services.yaml         # Order 3: Service trust extraction
    ├── iam/
    │   └── link_policies_to_roles.yaml            # Order 4: Policy attachment metadata
    ├── set_admin_administrator_access.yaml        # Order 10: Admin flag (managed policy)
    ├── set_admin_inline_wildcard.yaml             # Order 11: Admin flag (wildcard)
    ├── set_privileged_access.yaml                 # Order 12: Privileged flag
    ├── set_ssm_enabled_roles.yaml                 # Order 13: SSM-enabled flag
    └── privesc/
        ├── method_01_iam_create_policy_version.yaml
        ├── method_02_iam_set_default_policy_version.yaml
        ├── method_03_iam_create_access_key.yaml
        ├── method_04_iam_create_login_profile.yaml
        ├── method_05_iam_update_login_profile.yaml
        ├── method_06_iam_attach_user_policy.yaml
        ├── method_07_iam_attach_group_policy.yaml
        ├── method_08_iam_attach_role_policy.yaml
        ├── method_09_iam_put_user_policy.yaml
        ├── method_10_iam_put_group_policy.yaml
        ├── method_11_iam_put_role_policy.yaml
        ├── method_12_iam_add_user_to_group.yaml
        ├── method_13_iam_update_assume_role_policy.yaml
        ├── method_14_iam_pass_role_lambda.yaml
        ├── method_15_iam_pass_role_ec2.yaml
        ├── method_16_iam_pass_role_cloudformation.yaml
        ├── method_17_iam_pass_role_datapipeline.yaml
        ├── method_18_iam_pass_role_glue.yaml
        ├── method_19_iam_pass_role_sagemaker.yaml
        ├── method_20_lambda_update_function_code.yaml
        ├── method_21_lambda_create_event_source_mapping.yaml
        ├── method_22_sts_assume_role.yaml
        ├── method_23_ssm_send_command.yaml
        ├── method_24_ssm_start_session.yaml
        ├── method_25_ec2_ssm_association.yaml
        ├── method_26_codestar_create_project.yaml
        ├── method_27_codebuild_create_project.yaml
        └── method_28_iam_create_service_linked_role.yaml
```

## Execution Order

Queries are executed in ascending `order` field:

1. **Order 0-4**: Base enrichment (metadata, resource links, trust relationships)
2. **Order 10-13**: Admin/privilege detection
3. **Order 101-128**: Privilege escalation path detection (28 methods)

## YAML Format

Each query follows this structure:

```yaml
id: aws/enrich/category/name
name: Human-Readable Name
platform: aws
type: enrich
category: metadata|admin-detection|privesc|ssm|trust-extraction|resource-to-role|iam
description: |
  Multi-line description of what this query detects.
severity: info|low|medium|high|critical
order: N  # execution order (lower = first)
cypher: |
  MATCH ...
  MERGE ...
  RETURN count(*) as result
```

## Query Categories

- **metadata**: Account-level enrichment
- **resource-to-role**: Links compute resources to IAM roles
- **trust-extraction**: Extracts trust relationships from AssumeRolePolicyDocument
- **iam**: Policy attachment metadata
- **admin-detection**: Flags principals with admin-level access
- **ssm**: SSM session manager capability detection
- **privesc**: Privilege escalation path detection (28 IAM attack methods)

## Graph Schema

**Node Labels:**
- `Principal` (parent label for User, Role, Group)
- `User`, `Role`, `Group` (IAM principals)
- `Resource` (S3, EC2, Lambda, etc.)
- `ServicePrincipal` (AWS service principals)

**Relationship Types:**
- `CAN_ASSUME` - Trust relationship (principal → role or service → role)
- `HAS_ROLE` - Resource assignment (EC2/Lambda → role)
- `CAN_PRIVESC` - Privilege escalation path (attacker → victim)
- Action-based: `IAM_PASSROLE`, `S3_GETOBJECT`, `LAMBDA_CREATEFUNCTION`, etc.

**Key Properties:**
- `_resourceType`: AWS CloudFormation type (e.g., "AWS::IAM::User")
- `_enriched`: Boolean flag for base enrichment completion
- `_is_admin`: Boolean flag for admin principals
- `_admin_reason`: String describing why flagged as admin
- `_is_privileged`: Boolean flag for high-privilege principals
- `_ssm_enabled`: Boolean flag for SSM-capable roles
- `_policy_count`: Number of attached managed policies

## Embedding in Go Binary

Queries are embedded via `//go:embed` directive in the query loader:

```go
//go:embed enrich/**/*.yaml
var enrichFS embed.FS
```

The loader walks the embedded filesystem, parses YAML, and builds an in-memory query registry sorted by `order` field.

## Testing

Integration tests verify:
1. Query parsing and validation
2. Execution against test graph data
3. Expected node/relationship creation
4. Order-based execution sequence

See `pkg/graph/queries/enrich_test.go` for test suite.

## Privilege Escalation Methods

The 28 privesc methods are based on Rhino Security Labs' AWS IAM privilege escalation research. Each method represents a distinct attack vector where IAM permissions can be chained to gain elevated access.

### Method Categories

**Direct Policy Modification (1-11, 13):**
- Modify existing policies or create new ones
- Attach/put policies to principals
- Update trust policies

**PassRole Exploits (14-19):**
- Combine `iam:PassRole` with service creation permissions
- Execute code with elevated role permissions via:
  - Lambda functions (14)
  - EC2 instances (15)
  - CloudFormation stacks (16)
  - DataPipeline pipelines (17)
  - Glue jobs (18)
  - SageMaker notebooks (19)

**Service Abuse (20-25):**
- Modify Lambda function code (20)
- Trigger functions with malicious input (21)
- Assume roles directly (22)
- Execute commands via SSM (23-25)

**CI/CD Exploitation (26-27):**
- Create CodeStar/CodeBuild projects with elevated roles

**Service-Linked Roles (28):**
- Create service-linked roles with predefined permissions

## References

- Rhino Security Labs: AWS IAM Privilege Escalation Methods
- AWS IAM documentation: AssumeRolePolicyDocument, trust policies
- Neo4j Cypher documentation
