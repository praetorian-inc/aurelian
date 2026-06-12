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
    └── privesc/                                   # Order 100: 89 privilege-escalation methods
        └── <service>_<action>.yaml                # one YAML per attack method (see inventory below)
```

The privesc directory holds **89** method YAMLs (run `ls pkg/graph/queries/enrich/aws/privesc/*.yaml | wc -l` to confirm). The
full per-method listing is the [Privilege Escalation Methods](#privilege-escalation-methods)
section below rather than duplicated here.

## Execution Order

Queries are executed in ascending `order` field:

1. **Order 0-4**: Base enrichment (metadata, resource links, trust relationships)
2. **Order 10-13**: Admin/privilege detection
3. **Order 100**: Privilege escalation path detection (privesc methods, mutually order-independent)

## Cross-cutting privesc-method guards (Phase 2)

Reusable Cypher clauses applied to every corrected CAN_PRIVESC method (depend on the
order 10-13 enrichers having run). Apply these mechanically when fanning out a method:

- **Admin-as-source exclusion** (every method): `coalesce(attacker._is_admin, false) <> true`.
- **Self-target exclusion** (every non-self-escalation method):
  `coalesce(target.Arn, target.arn) <> coalesce(attacker.Arn, attacker.arn)`.
  Genuine self-escalation methods deliberately MERGE a self-loop instead.
- **Lateral-vs-admin severity tiering** on the privesc target:
  `severity = 'high'` when `target._is_admin`, `'medium'` when `target._is_privileged`
  (not admin), and SUPPRESS (do not emit) when neither — EXCEPT trust-backed
  direct-takeover (e.g. `sts:AssumeRole` via a real `CAN_ASSUME` edge), which fails-OPEN
  (emits even on a sparse target whose privilege is unknown) because the takeover is the
  finding.
- **No APOC**: JSON-string props (`AttachedManagedPolicies`, `InstanceProfileList`,
  `AssumeRolePolicyDocument`) are matched with `CONTAINS`, never parsed.

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
- **privesc**: Privilege escalation path detection (89 IAM attack methods)

## Graph Schema

**Node Labels:**
- `Principal` (parent label for User, Role, Group)
- `User`, `Role`, `Group` (IAM principals)
- `Resource` (S3, EC2, Lambda, etc.)
- `ServicePrincipal` (AWS service principals)

**Relationship Types:**
- `CAN_ASSUME` - Trust relationship (principal → role or service → role)
- `HAS_ROLE` - Resource assignment (EC2/Lambda → role)
- `CAN_PRIVESC` - Privilege escalation path (attacker → victim). Multi-edge: `method`
  is part of the edge identity, so each distinct attack method between the same
  (attacker, target) pair is its own edge (with its own `severity`)
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

There are **89** privesc method YAMLs, originally seeded from Rhino Security Labs' AWS IAM
privilege escalation research and expanded with the pathfinding.cloud gap-analysis set
(Phase 2). Each method is one YAML in `aws/privesc/` and represents a distinct attack vector
where IAM permissions can be chained to gain elevated access. All run at `order: 100` and
MERGE a `CAN_PRIVESC` edge to a correctly-scoped target (self-loop / passed role / reached
role / resource service role / service stub).

`CAN_PRIVESC` is a **multi-edge** relationship: each method MERGEs with its `method`
string as part of the edge identity (`MERGE (attacker)-[pe:CAN_PRIVESC {method: '<M>'}]->(target)`),
so distinct methods between the same (attacker, target) pair are **distinct edges** —
one edge per method — each carrying its own `severity`. This replaces the older
single-edge-per-pair model, where a shared `pe.method` property was overwritten
(last-write-wins) by whichever method ran last. The analysis query
(`analysis/aws/privesc_paths.yaml`) walks these edges to enumerate distinct
method-paths to admin, bounded by a deterministic `LIMIT 2000` guardrail against
path explosion over parallel per-method edges.

> Maintenance: this inventory is generated by listing the directory. To refresh after
> adding/removing a method, run `ls pkg/graph/queries/enrich/aws/privesc/*.yaml | wc -l`
> for the count and `ls pkg/graph/queries/enrich/aws/privesc/*.yaml | xargs -n1 basename`
> for the per-method list.

### Method Inventory (by service)

**IAM direct policy / trust modification & principal access (23):**
- `iam_create_policy_version`, `iam_set_default_policy_version`
- `iam_attach_user_policy`, `iam_attach_group_policy`, `iam_attach_role_policy`
- `iam_put_user_policy`, `iam_put_group_policy`, `iam_put_role_policy`
- `iam_add_user_to_group`, `iam_update_assume_role_policy`
- `iam_create_access_key`, `iam_create_login_profile`, `iam_update_login_profile`
- `iam_create_service_linked_role`
- `iam_pass_role_lambda`, `iam_pass_role_ec2`, `iam_pass_role_cloudformation`,
  `iam_pass_role_datapipeline`, `iam_pass_role_glue`, `iam_pass_role_sagemaker`
- `passrole_modify_policy`, `update_assume_role_passrole_service`
- `sts_assume_role`

**EC2 / AutoScaling / ImageBuilder (9):**
- `ec2_instance_connect`, `ec2_launch_template_version`, `ec2_modify_instance_attribute`,
  `ec2_replace_instance_profile`, `ec2_request_spot_instances`, `ec2_ssm_association`
- `autoscaling_launch_template`
- `imagebuilder_create_pipeline`, `imagebuilder_createimage`

**Lambda (5):**
- `lambda_update_function_code`, `lambda_updatecode_invoke`, `lambda_add_permission`,
  `lambda_create_event_source_mapping`, `lambda_passrole_createfunction_addpermission`

**CloudFormation (4):**
- `cloudformation_changeset`, `cloudformation_create_stackset`, `cloudformation_update_stack`,
  `cloudformation_update_stackset`

**CodeBuild / CodeDeploy / CodeStar (5):**
- `codebuild_create_project`, `codebuild_update_project`, `codebuild_start_build`
- `codedeploy_create_deployment`
- `codestar_create_project`

**Glue (9):**
- `glue_create_dev_endpoint`, `glue_update_dev_endpoint`, `glue_update_job`, `glue_create_session`
- `glue_createjob_createtrigger`, `glue_updatejob_createtrigger`
- `glue_createjob_startjobrun`, `glue_updatejob_startjobrun`, `glue_createsession_runstatement`

**ECS (4):**
- `ecs_create_service`, `ecs_start_task`, `ecs_execute_command`, `ecs_passrole_runtask`

**Step Functions (3):**
- `stepfunctions_create`, `stepfunctions_update`, `stepfunctions_create_startexecution`

**SageMaker (4):**
- `sagemaker_lifecycle_config`, `sagemaker_presigned_url`, `sagemaker_processing_job`,
  `sagemaker_training_job`

**SSM (4):**
- `ssm_send_command`, `ssm_start_session`, `ssm_start_automation`,
  `ssm_createdocument_startautomation`

**EMR / Batch / Braket / GameLift / Omics / Kinesis Analytics (12):**
- `emr_run_job_flow`, `emr_serverless`, `emr_serverless_startjobrun`
- `batch_passrole`, `batch_submit_job`
- `braket_create_job`
- `gamelift_create_fleet`, `gamelift_createbuild_createfleet`
- `omics_create_workflow`, `omics_startrun`
- `kinesis_analytics`, `kinesisanalytics_startapplication`

**Bedrock AgentCore / Cognito / App Runner / Amplify / Scheduler (7):**
- `bedrock_create_code_interpreter`, `bedrock_access_code_interpreter`
- `cognito_set_identity_pool_roles`
- `apprunner_create_service`, `apprunner_update_service`
- `amplify_create_app`
- `scheduler_create_schedule`

## References

- Rhino Security Labs: AWS IAM Privilege Escalation Methods
- AWS IAM documentation: AssumeRolePolicyDocument, trust policies
- Neo4j Cypher documentation
