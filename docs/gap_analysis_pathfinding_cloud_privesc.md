# Gap Analysis: pathfinding.cloud vs Aurelian Privesc Coverage

**Date:** 2026-06-02  
**Reference:** LAB-3908  
**Source:** https://pathfinding.cloud/labs/ (122 labs catalogued)  
**Scope:** AWS only. Azure/GCP deferred pending LAB-3742.

---

## Summary

| Status   | Count | Notes |
|----------|-------|-------|
| Covered  | 42    | Existing methods 01–42 detect these |
| Partial  | 6     | Individual permissions detected, compound path not modelled |
| Missing  | 30    | New methods 43–72 added in this PR |
| Out of scope | 44 | Bucket-target, cross-account multi-hop, CSPM misconfigs |

---

## Coverage Classification

### COVERED — existing methods detect these techniques

| PLABS ID | Aurelian Method | Key Permission |
|----------|----------------|----------------|
| iam-001-to-admin | method_01 | iam:CreatePolicyVersion |
| iam-002-to-admin | method_03 | iam:CreateAccessKey |
| iam-003-to-admin | method_03 | iam:CreateAccessKey (key rotation variant) |
| iam-004-to-admin | method_04 | iam:CreateLoginProfile |
| iam-005-to-admin | method_11 | iam:PutRolePolicy |
| iam-006-to-admin | method_05 | iam:UpdateLoginProfile |
| iam-007-to-admin | method_09 | iam:PutUserPolicy |
| iam-008-to-admin | method_06 | iam:AttachUserPolicy |
| iam-009-to-admin | method_08 | iam:AttachRolePolicy |
| iam-010-to-admin | method_07 | iam:AttachGroupPolicy |
| iam-011-to-admin | method_10 | iam:PutGroupPolicy |
| iam-012-to-admin | method_13 | iam:UpdateAssumeRolePolicy |
| iam-013-to-admin | method_12 | iam:AddUserToGroup |
| iam-014-to-admin | method_06 | iam:AttachUserPolicy (cross-user) |
| iam-016-to-admin | method_02 | iam:SetDefaultPolicyVersion |
| sts-001-to-admin | method_22 | sts:AssumeRole |
| lambda-001-to-admin | method_14 | iam:PassRole + lambda:CreateFunction |
| lambda-002-to-admin | method_21 | lambda:CreateEventSourceMapping |
| lambda-003-to-admin | method_20 | lambda:UpdateFunctionCode |
| lambda-004-to-admin | method_39 | lambda:UpdateFunctionCode + lambda:InvokeFunction |
| lambda-006-to-admin | method_14 | iam:PassRole + lambda:CreateFunction |
| ec2-001-to-admin | method_15 | iam:PassRole + ec2:RunInstances |
| ec2-004-to-admin | method_15 | iam:PassRole + ec2:RunInstances (spot variant) |
| cloudformation-001-to-admin | method_16 | iam:PassRole + cloudformation:CreateStack |
| cloudformation-002-to-admin | method_30 | iam:PassRole + cloudformation:UpdateStack |
| cloudformation-005-to-admin | method_31 | iam:PassRole + cloudformation:CreateChangeSet + ExecuteChangeSet |
| datapipeline-001-to-admin | method_17 | iam:PassRole + datapipeline:CreatePipeline |
| glue-002-to-admin | method_29 | glue:UpdateDevEndpoint |
| glue-003-to-admin | method_18 | iam:PassRole + glue:CreateJob |
| glue-004-to-admin | method_18 | iam:PassRole + glue:CreateJob (trigger variant) |
| sagemaker-001-to-admin | method_19 | iam:PassRole + sagemaker:CreateNotebookInstance |
| sagemaker-002-to-admin | method_36 | iam:PassRole + sagemaker:CreateTrainingJob |
| sagemaker-003-to-admin | method_37 | iam:PassRole + sagemaker:CreateProcessingJob |
| sagemaker-004-to-admin | method_35 | sagemaker:CreatePresignedNotebookInstanceUrl |
| ec2-005-to-admin | method_38 | iam:PassRole + ec2:CreateLaunchTemplate + autoscaling:CreateAutoScalingGroup |
| ecs-002-to-admin | method_32 | iam:PassRole + ecs:RunTask |
| ecs-004-to-admin | method_32 | iam:PassRole + ecs:RunTask (Fargate variant) |
| ecs-008-to-admin | method_32 | iam:PassRole + ecs:RunTask (override variant) |
| ssm-001-to-admin | method_24 | ssm:StartSession |
| ssm-002-to-admin | method_23 | ssm:SendCommand |
| bedrock-001-to-admin | method_40 | iam:PassRole + bedrock-agentcore:CreateCodeInterpreter |
| codebuild-001-to-admin | method_27 | iam:PassRole + codebuild:CreateProject |
| codebuild-002-to-admin | method_33 | codebuild:StartBuild |
| codebuild-003-to-admin | method_33 | codebuild:StartBuildBatch |
| codebuild-004-to-admin | method_27 | iam:PassRole + codebuild:CreateProject (batch variant) |

### PARTIAL — individual permissions detected but compound path not explicitly modelled

| PLABS ID | Existing Coverage | Gap |
|----------|-----------------|-----|
| iam-015-to-admin | method_06 (AttachUserPolicy) + method_03 (CreateAccessKey) individually | Compound cross-user escalation chain not single-edge |
| iam-017-to-admin | method_11 (PutRolePolicy) + method_22 (AssumeRole) individually | Two-step modify-then-assume not single-edge |
| iam-018-to-admin | method_06/method_03 individually | User-to-user lateral movement via separate edges |
| iam-019-to-admin | method_41 (PassRole + AttachRolePolicy) partially | UpdateAssumeRolePolicy + AttachRolePolicy compound |
| iam-020-to-admin | method_42 (UpdateAssumeRolePolicy + PassRole) partially | PutRolePolicy + UpdateAssumeRolePolicy compound |
| iam-021-to-admin | method_42 partially | Inline policy + trust policy update compound |

### MISSING → IMPLEMENTED (methods 43–72)

| PLABS ID | New Method | Key Permission(s) |
|----------|-----------|-------------------|
| apprunner-001-to-admin | method_43 | iam:PassRole + apprunner:CreateService |
| apprunner-002-to-admin | method_44 | apprunner:UpdateService |
| batch-001-to-admin | method_45 | iam:PassRole + batch:RegisterJobDefinition |
| batch-002-to-admin | method_46 | batch:SubmitJob |
| braket-001-to-admin | method_47 | iam:PassRole + braket:CreateJob |
| cloudformation-003-to-admin | method_48 | iam:PassRole + cloudformation:CreateStackSet |
| cloudformation-004-to-admin | method_49 | iam:PassRole + cloudformation:UpdateStackSet |
| codedeploy-001-to-admin | method_50 | codedeploy:CreateDeployment |
| cognito-identity-001-to-admin | method_51 | iam:PassRole + cognito-identity:SetIdentityPoolRoles |
| ec2-003-to-admin | method_52 | ec2-instance-connect:SendSSHPublicKey |
| ec2-002-to-admin | method_53 | ec2:ReplaceIamInstanceProfileAssociation |
| ecs-001-to-admin / ecs-003-to-admin | method_54 | iam:PassRole + ecs:CreateService |
| ecs-005-to-admin / ecs-009-to-admin | method_55 | iam:PassRole + ecs:StartTask |
| ecs-006-to-admin | method_56 | ecs:ExecuteCommand |
| emr-001-to-admin | method_57 | iam:PassRole + elasticmapreduce:RunJobFlow |
| emrserverless-001-to-admin | method_58 | iam:PassRole + emr-serverless:CreateApplication |
| gamelift-001-to-admin | method_59 | iam:PassRole + gamelift:CreateFleet |
| glue-001-to-admin | method_60 | iam:PassRole + glue:CreateDevEndpoint |
| glue-005-to-admin / glue-006-to-admin | method_61 | iam:PassRole + glue:UpdateJob |
| glue-007-to-admin | method_62 | iam:PassRole + glue:CreateSession |
| imagebuilder-001-to-admin | method_63 | iam:PassRole + imagebuilder:CreateInfrastructureConfiguration |
| kinesisanalytics-001-to-admin | method_64 | iam:PassRole + kinesisanalytics:CreateApplication |
| lambda-005-to-admin | method_65 | lambda:UpdateFunctionCode + lambda:AddPermission |
| omics-001-to-admin | method_66 | iam:PassRole + omics:CreateWorkflow |
| sagemaker-005-to-admin | method_67 | sagemaker:UpdateNotebookInstanceLifecycleConfig |
| scheduler-001-to-admin | method_68 | iam:PassRole + scheduler:CreateSchedule |
| ssm-003-to-admin | method_69 | iam:PassRole + ssm:StartAutomationExecution |
| stepfunctions-001-to-admin | method_70 | iam:PassRole + states:CreateStateMachine |
| stepfunctions-002-to-admin | method_71 | iam:PassRole + states:UpdateStateMachine |
| bedrock-002-to-admin | method_72 | bedrock-agentcore:InvokeSession |

### OUT OF SCOPE

The following pathfinding.cloud labs are excluded from Aurelian's current privesc graph scope:

**Bucket-target labs** (44 total) — target a specific S3 bucket rather than full admin escalation. Aurelian's `CAN_PRIVESC` edges model admin-level escalation paths. Data exfiltration paths to specific resources are a separate modelling effort.
- `*-to-bucket` variants: iam-002/003/004/005/006/009/012-to-bucket, lambda-001..006-to-bucket, ssm-001/002-to-bucket, sts-001-to-bucket, glue-001/002-to-bucket, datapipeline-001-to-bucket, ec2-003-to-bucket, exclusive-resource-policy-to-bucket, resource-policy-bypass-to-bucket, role-chain-to-s3-to-bucket, github-oidc-cross-account-pivot-to-bucket

**Cross-account multi-hop labs** — require modelling relationships between accounts (different graph topology). Track as follow-up once cross-account edges are supported:
- dev-to-prod-multi-hop-both-accounts-to-admin
- dev-to-prod-via-direct-role-assumption-to-admin
- dev-to-prod-via-lambda-code-injection-to-admin
- dev-to-prod-via-lambda-passrole-to-admin
- dev-to-prod-via-root-trust-assumption-to-admin
- dev-to-prod-via-ssm-startsession-to-ec2-with-admin-role
- simple-role-assumption-to-admin (cross-account variants)
- root-trust-role-assumption-to-admin
- multi-hop-both-sides-to-admin
- lambda-invoke-update-to-admin
- passrole-lambda-admin-to-admin
- ssm-startsession-ec2-admin-to-admin
- sts-001-to-ecs-002-to-admin-to-admin

**CSPM misconfigurations** — static resource state, not active exploitation paths:
- cspm-ec2-001-to-admin (EC2 instance with privileged role attached)
- public-lambda-with-admin-to-admin (publicly accessible Lambda with admin role)

**Composite demo labs**:
- multiple-paths-combined-to-admin (multi-technique demonstration)

---

## Follow-ups

- **Azure/GCP**: defer until IAM graphs land (LAB-3742 / Resource Relationships)
- **Bucket-target paths**: consider adding `CAN_ACCESS_BUCKET` edge type for data exfiltration paths
- **Cross-account edges**: requires cross-account graph topology work before these labs can be modelled
- **Partial IAM compound methods** (iam-015/017/018/019/020/021): consider whether single compound-edge detection adds value over individual edge detection
