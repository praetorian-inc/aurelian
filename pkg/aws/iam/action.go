package iam

import (
	"slices"
	"strings"
)

type Action string

func (a *Action) Service() string {
	split := strings.Split(string(*a), ":")
	if len(split) != 2 {
		return ""
	}
	return split[0]
}

func IsPrivEscAction(action string) bool {
	return slices.Contains(privEscActions, action)
}

var privEscActions = []string{
	// Amplify
	"amplify:CreateApp",
	"amplify:CreateBranch",
	"amplify:StartJob",
	// App Runner (methods 43–44)
	"apprunner:CreateService",
	"apprunner:UpdateService",
	// AWS Batch (methods 45–46)
	"batch:RegisterJobDefinition",
	"batch:SubmitJob",
	// Amazon Braket
	"braket:CreateJob",
	// CloudFormation (methods 16, 30, 31, 48–49)
	"cloudformation:CreateChangeSet",
	"cloudformation:CreateStack",
	"cloudformation:CreateStackInstances",
	"cloudformation:CreateStackSet",
	"cloudformation:ExecuteChangeSet",
	"cloudformation:SetStackPolicy",
	"cloudformation:UpdateStack",
	"cloudformation:UpdateStackSet",
	// CodeBuild (methods 27, 33–34)
	"codebuild:CreateProject",
	"codebuild:StartBuild",
	"codebuild:StartBuildBatch",
	"codebuild:UpdateProject",
	// CodeDeploy
	"codedeploy:CreateDeployment",
	// Data Pipeline
	"datapipeline:ActivatePipeline",
	"datapipeline:CreatePipeline",
	"datapipeline:PutPipelineDefinition",
	// CodeStar
	"codestar:AssociateTeamMember",
	"codestar:CreateProject",
	// Cognito Identity: SetIdentityPoolRoles binds the passed role to the pool;
	// GetId + GetCredentialsForIdentity are the credential-retrieval half the
	// cognito_set_identity_pool_roles.yaml guard EXISTS-requires to obtain pool credentials
	// and assume the bound role. All three must be allowlisted for the evaluator to emit the
	// COGNITO-IDENTITY_* edges (additive coverage data).
	"cognito-identity:GetCredentialsForIdentity",
	"cognito-identity:GetId",
	"cognito-identity:SetIdentityPoolRoles",
	// EC2 (methods 15, 38, 52–53, 73–76)
	"ec2:CreateLaunchTemplate",
	"ec2:CreateLaunchTemplateVersion",
	"ec2:ModifyInstanceAttribute",
	"ec2:ModifyLaunchTemplate",
	"ec2:ReplaceIamInstanceProfileAssociation",
	"ec2:RequestSpotInstances",
	"ec2:RunInstances",
	"ec2:StartInstances",
	"ec2:StopInstances",
	"ec2-instance-connect:SendSSHPublicKey",
	// ECS (methods 32, 54–56)
	"ecs:CreateService",
	"ecs:ExecuteCommand",
	"ecs:RegisterTaskDefinition",
	"ecs:RunTask",
	"ecs:StartTask",
	// EMR
	"elasticmapreduce:RunJobFlow",
	// EMR Serverless (methods 58, 85)
	"emr-serverless:CreateApplication",
	"emr-serverless:StartJobRun",
	// GameLift (methods 59, 88)
	"gamelift:CreateBuild",
	"gamelift:CreateFleet",
	// Glue (methods 18, 29, 60–62, 77–78, 80–82)
	"glue:CreateDevEndpoint",
	"glue:CreateJob",
	"glue:CreateSession",
	"glue:CreateTrigger",
	"glue:RunStatement",
	"glue:StartJobRun",
	"glue:UpdateDevEndpoint",
	"glue:UpdateJob",
	// IAM (methods 01–13, 28)
	"iam:AddUserToGroup",
	"iam:AttachGroupPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"iam:CreatePolicyVersion",
	"iam:CreateRole",
	"iam:CreateServiceLinkedRole",
	"iam:CreateUser",
	"iam:DeleteAccessKey",
	"iam:PassRole",
	"iam:PutGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
	"iam:UpdateLoginProfile",
	// EC2 Image Builder (methods 63, 89)
	"imagebuilder:CreateComponent",
	"imagebuilder:CreateImage",
	"imagebuilder:CreateImageRecipe",
	"imagebuilder:CreateInfrastructureConfiguration",
	// Kinesis Analytics (methods 64, 86)
	"kinesisanalytics:CreateApplication",
	"kinesisanalytics:StartApplication",
	// Lambda (methods 14, 20–21, 39, 65)
	"lambda:AddPermission",
	"lambda:CreateEventSourceMapping",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"lambda:UpdateFunctionCode",
	"lambda:UpdateFunctionConfiguration",
	// HealthOmics (methods 66, 87)
	"omics:CreateWorkflow",
	"omics:StartRun",
	// AutoScaling
	"autoscaling:CreateAutoScalingGroup",
	"autoscaling:CreateLaunchConfiguration",
	// EventBridge Scheduler
	"scheduler:CreateSchedule",
	// SageMaker (methods 19, 35–37, 67)
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"sagemaker:UpdateNotebookInstanceLifecycleConfig",
	// SSM (methods 23–25, 69, 84)
	"ssm:CreateAssociation",
	"ssm:CreateDocument",
	"ssm:ResumeSession",
	"ssm:SendCommand",
	"ssm:StartAutomationExecution",
	"ssm:StartSession",
	// Step Functions (methods 70–71, 83)
	"states:CreateStateMachine",
	"states:StartExecution",
	"states:UpdateStateMachine",
	// STS
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
	// Bedrock AgentCore (methods 40, 72)
	"bedrock-agentcore:CreateCodeInterpreter",
	"bedrock-agentcore:InvokeCodeInterpreter",
	"bedrock-agentcore:InvokeSession",
	"bedrock-agentcore:StartCodeInterpreterSession",
}
