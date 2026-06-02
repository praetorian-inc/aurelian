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
	// App Runner (methods 43–44)
	"apprunner:CreateService",
	"apprunner:UpdateService",
	// AWS Batch (methods 45–46)
	"batch:RegisterJobDefinition",
	"batch:SubmitJob",
	// Amazon Braket (method 47)
	"braket:CreateJob",
	// CloudFormation (methods 16, 30, 31, 48–49)
	"cloudformation:CreateChangeSet",
	"cloudformation:CreateStack",
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
	// CodeDeploy (method 50)
	"codedeploy:CreateDeployment",
	// CodeStar (method 26)
	"codestar:AssociateTeamMember",
	"codestar:CreateProject",
	// Cognito Identity (method 51)
	"cognito-identity:SetIdentityPoolRoles",
	// EC2 (methods 15, 38, 52–53)
	"ec2:CreateLaunchTemplate",
	"ec2:ReplaceIamInstanceProfileAssociation",
	"ec2:RunInstances",
	"ec2-instance-connect:SendSSHPublicKey",
	// ECS (methods 32, 54–56)
	"ecs:CreateService",
	"ecs:ExecuteCommand",
	"ecs:RegisterTaskDefinition",
	"ecs:RunTask",
	"ecs:StartTask",
	// EMR (method 57)
	"elasticmapreduce:RunJobFlow",
	// EMR Serverless (method 58)
	"emr-serverless:CreateApplication",
	// GameLift (method 59)
	"gamelift:CreateFleet",
	// Glue (methods 18, 29, 60–62)
	"glue:CreateDevEndpoint",
	"glue:CreateJob",
	"glue:CreateSession",
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
	"iam:PassRole",
	"iam:PutGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
	"iam:UpdateLoginProfile",
	// EC2 Image Builder (method 63)
	"imagebuilder:CreateInfrastructureConfiguration",
	// Kinesis Analytics (method 64)
	"kinesisanalytics:CreateApplication",
	// Lambda (methods 14, 20–21, 39, 65)
	"lambda:AddPermission",
	"lambda:CreateEventSourceMapping",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"lambda:UpdateFunctionCode",
	"lambda:UpdateFunctionConfiguration",
	// HealthOmics (method 66)
	"omics:CreateWorkflow",
	// AutoScaling (method 38)
	"autoscaling:CreateAutoScalingGroup",
	"autoscaling:CreateLaunchConfiguration",
	// EventBridge Scheduler (method 68)
	"scheduler:CreateSchedule",
	// SageMaker (methods 19, 35–37, 67)
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"sagemaker:UpdateNotebookInstanceLifecycleConfig",
	// SSM (methods 23–25, 69)
	"ssm:CreateAssociation",
	"ssm:ResumeSession",
	"ssm:SendCommand",
	"ssm:StartAutomationExecution",
	"ssm:StartSession",
	// Step Functions (methods 70–71)
	"states:CreateStateMachine",
	"states:UpdateStateMachine",
	// STS (method 22)
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
	// Bedrock AgentCore (methods 40, 72)
	"bedrock-agentcore:CreateCodeInterpreter",
	"bedrock-agentcore:InvokeSession",
}
