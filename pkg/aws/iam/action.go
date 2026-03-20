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
	"cloudformation:CreateChangeSet",
	"cloudformation:CreateStack",
	"cloudformation:ExecuteChangeSet",
	"cloudformation:SetStackPolicy",
	"cloudformation:UpdateStack",
	"cloudformation:UpdateStackSet",
	"codebuild:CreateProject",
	"codebuild:StartBuild",
	"codebuild:StartBuildBatch",
	"codebuild:UpdateProject",
	"codestar:AssociateTeamMember",
	"codestar:CreateProject",
	"ec2:CreateLaunchTemplate",
	"ec2:RunInstances",
	"ecs:RegisterTaskDefinition",
	"ecs:RunTask",
	"glue:CreateDevEndpoint",
	"glue:UpdateDevEndpoint",
	"iam:AddUserToGroup",
	"iam:AttachGroupPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"iam:CreatePolicyVersion",
	"iam:CreateUser",
	"iam:CreateRole",
	"iam:PassRole",
	"iam:PutGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
	"iam:UpdateLoginProfile",
	"autoscaling:CreateAutoScalingGroup",
	"autoscaling:CreateLaunchConfiguration",
	"lambda:CreateEventSourceMapping",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"lambda:UpdateFunctionCode",
	"lambda:UpdateFunctionConfiguration",
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"ssm:SendCommand",
	"ssm:StartSession",
	"ssm:StartAutomationExecution",
	"ssm:ResumeSession",
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
}
