// Package structuralfacts extracts resource-to-role bindings from collected AWS
// resources and emits them as StructuralFact values. These facts feed the
// escalation solver's chain rules: a rule like codebuild_start_build fires only
// when a CodeBuild project with a privileged service role exists, so Aurelian
// must collect the project→role binding as an explicit structural fact.
//
// The collector runs AFTER the graph module enumerates resources (the same
// resource set that populates the Neo4j graph) and extracts role references from
// each resource's Properties map using the same property keys the existing YAML
// enrichers (resource_service_role.yaml, set_launch_template_role.yaml, etc.)
// match against.
package structuralfacts

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Fact type constants name the resource-to-role binding each fact captures.
const (
	FactCodeBuildServiceRole         = "codebuild_service_role"
	FactLaunchTemplateInstanceProfile = "launch_template_instance_profile"
	FactCloudFormationStackRole      = "cloudformation_stack_role"
	FactLambdaExecutionRole          = "lambda_execution_role"
	FactECSTaskRole                  = "ecs_task_role"
	FactGlueJobRole                  = "glue_job_role"
	FactGlueEndpointRole             = "glue_endpoint_role"
	FactAppRunnerServiceRole         = "apprunner_service_role"
	FactStepFunctionsRole            = "stepfunctions_role"
	FactSageMakerNotebookRole        = "sagemaker_notebook_role"
	FactBatchJobRole                 = "batch_job_role"
	FactBedrockInterpreterRole       = "bedrock_interpreter_role"
	FactInstanceProfile              = "instance_profile"
	FactCognitoAuthenticatedRole     = "cognito_authenticated_role"
	FactCognitoUnauthenticatedRole   = "cognito_unauthenticated_role"
	FactStackSetAdminRole            = "stackset_admin_role"
	FactStackSetExecutionRole        = "stackset_execution_role"
)

// extractor defines one resource-type → fact-type extraction: which property
// keys to read and how to map them to structural facts.
type extractor struct {
	resourceType string
	factType     string
	// propKeys lists the Properties keys that hold role references for this
	// resource type. Each non-empty value produces one StructuralFact.
	propKeys []string
}

// extractors is the registry of all supported resource-to-role extractions.
// The property keys match what each enumerator stores in output.AWSResource.Properties
// and what the YAML enrichers (resource_service_role.yaml, set_launch_template_role.yaml)
// read from the flattened properties JSON or promoted top-level props.
var extractors = []extractor{
	// Priority 1: the three original chain-rule facts.
	{"AWS::CodeBuild::Project", FactCodeBuildServiceRole, []string{"ServiceRole"}},
	{"AWS::EC2::LaunchTemplate", FactLaunchTemplateInstanceProfile, []string{"IamInstanceProfile"}},
	{"AWS::CloudFormation::Stack", FactCloudFormationStackRole, []string{"RoleARN"}},

	// Priority 2: remaining chain-rule facts from the expanded scope.
	{"AWS::CloudFormation::StackSet", FactStackSetAdminRole, []string{"AdministrationRoleARN"}},
	{"AWS::CloudFormation::StackSet", FactStackSetExecutionRole, []string{"ExecutionRoleName"}},
	{"AWS::Lambda::Function", FactLambdaExecutionRole, []string{"Role"}},
	{"AWS::ECS::TaskDefinition", FactECSTaskRole, []string{"TaskRoleArn"}},
	{"AWS::Glue::Job", FactGlueJobRole, []string{"Role"}},
	{"AWS::Glue::DevEndpoint", FactGlueEndpointRole, []string{"RoleArn"}},
	{"AWS::AppRunner::Service", FactAppRunnerServiceRole, []string{"InstanceRoleArn"}},
	{"AWS::StepFunctions::StateMachine", FactStepFunctionsRole, []string{"RoleArn"}},
	{"AWS::SageMaker::NotebookInstance", FactSageMakerNotebookRole, []string{"RoleArn"}},
	{"AWS::Batch::JobDefinition", FactBatchJobRole, []string{"JobRoleArn"}},
	{"AWS::BedrockAgentCore::CodeInterpreter", FactBedrockInterpreterRole, []string{"ExecutionRoleArn"}},
	{"AWS::EC2::Instance", FactInstanceProfile, []string{"IamInstanceProfile"}},
	{"AWS::Cognito::IdentityPool", FactCognitoAuthenticatedRole, []string{"authenticatedRole"}},
	{"AWS::Cognito::IdentityPool", FactCognitoUnauthenticatedRole, []string{"unauthenticatedRole"}},
}

// extractorIndex maps resource type to the extractor(s) that apply.
var extractorIndex map[string][]extractor

func init() {
	extractorIndex = make(map[string][]extractor, len(extractors))
	for _, e := range extractors {
		extractorIndex[e.resourceType] = append(extractorIndex[e.resourceType], e)
	}
}

// instanceProfileKeys lists the property keys that hold instance-profile
// references which may be bare names rather than ARNs.
var instanceProfileKeys = map[string]bool{
	"IamInstanceProfile": true,
}

// BuildInstanceProfileIndex builds a name→ARN lookup for IAM instance profiles
// from the GAAD roles' InstanceProfileList. Returns an empty (non-nil) map when
// gaad is nil or contains no instance profiles.
func BuildInstanceProfileIndex(gaad *types.AuthorizationAccountDetails) map[string]string {
	index := make(map[string]string)
	if gaad == nil {
		return index
	}
	gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		for _, ip := range role.InstanceProfileList {
			if ip.InstanceProfileName != "" && ip.Arn != "" {
				index[ip.InstanceProfileName] = ip.Arn
			}
		}
		return true
	})
	return index
}

// Collect walks the collected resources and returns all structural facts found.
// Each resource whose Properties carry a non-empty role reference produces one
// StructuralFact per role key.
//
// instanceProfileIndex is an optional name→ARN lookup (built by
// BuildInstanceProfileIndex) that resolves bare instance-profile names to full
// ARNs. Pass nil to skip resolution.
func Collect(resources store.Map[output.AWSResource], instanceProfileIndex map[string]string) []output.StructuralFact {
	var facts []output.StructuralFact
	resources.Range(func(_ string, r output.AWSResource) bool {
		exts, ok := extractorIndex[r.ResourceType]
		if !ok {
			return true
		}
		for _, ext := range exts {
			for _, key := range ext.propKeys {
				roleRef := propString(r.Properties, key)
				if roleRef == "" {
					continue
				}
				if instanceProfileKeys[key] {
					roleRef = resolveInstanceProfile(roleRef, instanceProfileIndex)
				}
				facts = append(facts, output.StructuralFact{
					FactType:     ext.factType,
					ResourceARN:  r.ARN,
					ResourceType: r.ResourceType,
					RoleARN:      roleRef,
					AccountID:    r.AccountRef,
					Region:       r.Region,
				})
			}
		}
		return true
	})
	return facts
}

// resolveInstanceProfile returns the ARN for ref. If ref is already an ARN
// (starts with "arn:") it is returned as-is. Otherwise it is looked up in the
// index; a miss returns the bare name unchanged.
func resolveInstanceProfile(ref string, index map[string]string) string {
	if strings.HasPrefix(ref, "arn:") {
		return ref
	}
	if index != nil {
		if resolved, ok := index[ref]; ok {
			return resolved
		}
	}
	return ref
}

// propString reads a string property from the Properties map.
// Returns "" for nil/absent/non-string values.
func propString(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	s, _ := props[key].(string)
	return s
}
