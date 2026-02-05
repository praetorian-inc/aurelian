package aws

import (
	"context"
	"slices"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

type Action string

func (a *Action) Service() string {
	split := strings.Split(string(*a), ":")
	if len(split) != 2 {
		return ""
	}
	return split[0]
}

func isPrivEscAction(action string) bool {
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
	"ec2:RunInstances",
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

// Helper function to expand wildcard actions
func expandActionsWithStage(actions types.DynaString) []string {
	expandedActions := make([]string, 0)

	// Create the link once and initialize it
	link := NewAWSExpandActionsLink(map[string]any{})
	if err := link.Initialize(); err != nil {
		// If initialization fails, return actions as-is
		return actions
	}

	// Process each action
	ctx := context.Background()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			// Use the link to expand wildcards
			link.ClearOutputs()
			_, err := link.Process(ctx, action)
			if err != nil {
				// On error, add the original action
				expandedActions = append(expandedActions, action)
				continue
			}

			// Collect expanded actions from link outputs
			for _, output := range link.Outputs() {
				if expanded, ok := output.(string); ok {
					expandedActions = append(expandedActions, expanded)
				}
			}
		} else {
			// Add non-wildcard actions directly
			expandedActions = append(expandedActions, action)
		}
	}

	return expandedActions
}

func ExtractActions(psl *types.PolicyStatementList) []string {
	actions := []string{}
	for _, statement := range *psl {
		if statement.Action != nil {
			expandedActions := expandActionsWithStage(*statement.Action)
			actions = append(actions, expandedActions...)
		}
	}
	return actions
}
