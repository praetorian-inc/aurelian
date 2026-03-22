package iamquick

import "github.com/praetorian-inc/aurelian/pkg/types"

// privescCombo defines a privilege escalation pattern: a named set of IAM actions
// that, when all are available to a principal, constitute a privesc path.
type privescCombo struct {
	Name    string
	Actions []string
}

// privescCombinations is the merged set of privilege escalation patterns from
// cybernest's GAAD analysis and Aurelian's graph module action sets.
var privescCombinations = []privescCombo{
	// STS
	{Name: "sts-federation", Actions: []string{"sts:GetFederationToken"}},
	{Name: "sts-assume", Actions: []string{"sts:AssumeRole"}},

	// EC2
	{Name: "ec2-passrole", Actions: []string{"ec2:RunInstances", "iam:PassRole"}},

	// Lambda
	{Name: "lambda-create", Actions: []string{"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"}},
	{Name: "lambda-update-code", Actions: []string{"lambda:InvokeFunction", "lambda:UpdateFunctionCode"}},
	{Name: "lambda-update-config", Actions: []string{"lambda:UpdateFunctionConfiguration"}},

	// CloudFormation
	{Name: "cfn-create-stack", Actions: []string{"cloudformation:CreateStack", "iam:PassRole"}},
	{Name: "cfn-update-stack", Actions: []string{"cloudformation:UpdateStack"}},
	{Name: "cfn-changeset", Actions: []string{"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"}},

	// Glue
	{Name: "glue-create-job", Actions: []string{"glue:CreateJob", "iam:PassRole"}},
	{Name: "glue-create-endpoint", Actions: []string{"glue:CreateDevEndpoint", "iam:PassRole"}},
	{Name: "glue-update-endpoint", Actions: []string{"glue:UpdateDevEndpoint"}},

	// IAM User manipulation
	{Name: "iam-create-user-put", Actions: []string{"iam:CreateUser", "iam:CreateAccessKey", "iam:PutUserPolicy"}},
	{Name: "iam-create-user-attach", Actions: []string{"iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy"}},
	{Name: "iam-update-user-put", Actions: []string{"iam:CreateAccessKey", "iam:PutUserPolicy"}},
	{Name: "iam-update-user-attach", Actions: []string{"iam:CreateAccessKey", "iam:AttachUserPolicy"}},

	// IAM Role manipulation
	{Name: "iam-create-role-put", Actions: []string{"iam:CreateRole", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"}},
	{Name: "iam-create-role-attach", Actions: []string{"iam:CreateRole", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"}},
	{Name: "iam-update-role-put", Actions: []string{"iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"}},
	{Name: "iam-update-role-attach", Actions: []string{"iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"}},

	// IAM Policy manipulation
	{Name: "iam-policy-version", Actions: []string{"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"}},

	// IAM Group manipulation
	{Name: "iam-add-to-group", Actions: []string{"iam:AddUserToGroup"}},
	{Name: "iam-group-put-policy", Actions: []string{"iam:PutGroupPolicy"}},
	{Name: "iam-group-attach-policy", Actions: []string{"iam:AttachGroupPolicy"}},

	// IAM Login manipulation
	{Name: "iam-create-login", Actions: []string{"iam:CreateLoginProfile"}},
	{Name: "iam-update-login", Actions: []string{"iam:UpdateLoginProfile"}},

	// ECS
	{Name: "ecs-run-task", Actions: []string{"ecs:RunTask", "iam:PassRole", "ecs:RegisterTaskDefinition"}},

	// DataPipeline
	{Name: "datapipeline-create", Actions: []string{"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline", "iam:PassRole"}},

	// SageMaker
	{Name: "sagemaker-notebook", Actions: []string{"sagemaker:CreateNotebookInstance", "iam:PassRole"}},
	{Name: "sagemaker-training", Actions: []string{"sagemaker:CreateTrainingJob", "iam:PassRole"}},
	{Name: "sagemaker-processing", Actions: []string{"sagemaker:CreateProcessingJob", "iam:PassRole"}},

	// CodeBuild
	{Name: "codebuild-existing", Actions: []string{"codebuild:StartBuild"}},
	{Name: "codebuild-existing-batch", Actions: []string{"codebuild:StartBuildBatch"}},
	{Name: "codebuild-create", Actions: []string{"codebuild:CreateProject", "iam:PassRole", "codebuild:StartBuild"}},
	{Name: "codebuild-create-batch", Actions: []string{"codebuild:CreateProject", "iam:PassRole", "codebuild:StartBuildBatch"}},
	{Name: "codebuild-update", Actions: []string{"codebuild:UpdateProject", "iam:PassRole", "codebuild:StartBuild"}},

	// SSM
	{Name: "ssm-send-command", Actions: []string{"ssm:SendCommand"}},
	{Name: "ssm-start-session", Actions: []string{"ssm:StartSession"}},
}

// collectPolicies returns all policy documents applicable to a principal,
// resolving managed policy ARNs against the GAAD's policy store and
// including group policies for users.
func collectPolicies(
	inlinePolicies []types.InlinePolicy,
	managedPolicies []types.ManagedPolicy,
	gaadPolicies func(arn string) *types.Policy,
) []types.Policy {
	var policies []types.Policy
	for _, ip := range inlinePolicies {
		policies = append(policies, ip.PolicyDocument)
	}
	for _, mp := range managedPolicies {
		if doc := gaadPolicies(mp.PolicyArn); doc != nil {
			policies = append(policies, *doc)
		}
	}
	return policies
}
