package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// StructuralFact represents a structural relationship between an AWS resource
// and the IAM role it operates as. These facts are used by the escalation
// solver to determine which privilege escalation paths are actually reachable:
// a chain rule like codebuild_start_build only fires when a CodeBuild project
// with a privileged service role exists.
//
// Each fact type names the resource-to-role binding it captures:
//
//   - codebuild_service_role:              CodeBuild project -> service role
//   - launch_template_instance_profile:    EC2 launch template -> instance profile role
//   - cloudformation_stack_role:           CloudFormation stack -> service role
//   - lambda_execution_role:               Lambda function -> execution role
//   - ecs_task_role:                       ECS task definition -> task role
//   - glue_job_role:                       Glue job -> role
//   - glue_endpoint_role:                  Glue dev endpoint -> role
//   - apprunner_service_role:              App Runner service -> instance role
//   - stepfunctions_role:                  Step Functions state machine -> execution role
//   - sagemaker_notebook_role:             SageMaker notebook -> execution role
//   - batch_job_role:                      Batch job definition -> role
//   - bedrock_interpreter_role:            Bedrock code interpreter -> execution role
//   - instance_profile:                    EC2 instance -> instance profile role
//   - cognito_authenticated_role:           Cognito identity pool -> authenticated role
//   - cognito_unauthenticated_role:         Cognito identity pool -> unauthenticated role (attacker-accessible)
//   - stackset_execution_role:              CloudFormation StackSet -> execution role
type StructuralFact struct {
	model.BaseAurelianModel

	// FactType identifies the kind of resource-to-role binding (e.g. "codebuild_service_role").
	FactType string `json:"fact_type"`

	// ResourceARN is the ARN of the resource (e.g. the CodeBuild project ARN).
	ResourceARN string `json:"resource_arn"`

	// ResourceType is the CloudControl type string (e.g. "AWS::CodeBuild::Project").
	ResourceType string `json:"resource_type"`

	// RoleARN is the ARN of the IAM role the resource operates as.
	// For launch_template_instance_profile, this may be a bare instance profile
	// name rather than a full ARN when the template was configured with a name
	// instead of an ARN. Consumers should handle both forms.
	RoleARN string `json:"role_arn"`

	// AccountID is the AWS account ID that owns the resource.
	AccountID string `json:"account_id"`

	// Region is the AWS region where the resource lives.
	Region string `json:"region,omitempty"`
}
