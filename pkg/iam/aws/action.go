package aws

import (
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/nebula/pkg/types"
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
	// return slices.Contains(privEscActions, action)
	return true
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
	"datapipeline:CreatePipeline",
	"datapipeline:PutPipelineDefinition",
	"ec2:RunInstances",
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
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
}

// Helper function to use AwsExpandActionsStage
func expandActionsWithStage(actions types.DynaString) []string {
	expandedActions := make([]string, 0)

	// Process each action
	for _, action := range actions {
		if strings.Contains(action, "*") {
			c := chain.NewChain(NewAWSExpandActionsLink())
			c.Send(action)
			c.Close()

			for o, ok := chain.RecvAs[string](c); ok; o, ok = chain.RecvAs[string](c) {
				expandedActions = append(expandedActions, o)
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
