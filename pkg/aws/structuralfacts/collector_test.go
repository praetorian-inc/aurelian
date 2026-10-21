package structuralfacts

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectCodeBuildServiceRole(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:codebuild:us-east-1:123456789012:project/build-proj", output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ResourceID:   "build-proj",
		ARN:          "arn:aws:codebuild:us-east-1:123456789012:project/build-proj",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"ServiceRole": "arn:aws:iam::123456789012:role/codebuild-service-role",
		},
	})

	facts := Collect(resources)

	var codebuildFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactCodeBuildServiceRole {
			codebuildFacts = append(codebuildFacts, f)
		}
	}

	require.Len(t, codebuildFacts, 1)
	assert.Equal(t, "arn:aws:codebuild:us-east-1:123456789012:project/build-proj", codebuildFacts[0].ResourceARN)
	assert.Equal(t, "AWS::CodeBuild::Project", codebuildFacts[0].ResourceType)
	assert.Equal(t, "arn:aws:iam::123456789012:role/codebuild-service-role", codebuildFacts[0].RoleARN)
	assert.Equal(t, "123456789012", codebuildFacts[0].AccountID)
	assert.Equal(t, "us-east-1", codebuildFacts[0].Region)
}

func TestCollectCodeBuildServiceRoleNoRole(t *testing.T) {
	// A CodeBuild project without a service role emits no fact.
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:codebuild:us-east-1:123456789012:project/roleless", output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ResourceID:   "roleless",
		ARN:          "arn:aws:codebuild:us-east-1:123456789012:project/roleless",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"ServiceRole": "",
		},
	})

	facts := Collect(resources)

	for _, f := range facts {
		if f.FactType == FactCodeBuildServiceRole {
			t.Errorf("expected no codebuild_service_role fact for roleless project, got %+v", f)
		}
	}
}

func TestCollectLaunchTemplateInstanceProfile(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:ec2:us-west-2:123456789012:launch-template/lt-abc123", output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ResourceID:   "lt-abc123",
		ARN:          "arn:aws:ec2:us-west-2:123456789012:launch-template/lt-abc123",
		AccountRef:   "123456789012",
		Region:       "us-west-2",
		Properties: map[string]any{
			"IamInstanceProfile": "arn:aws:iam::123456789012:instance-profile/prod-profile",
		},
	})

	facts := Collect(resources)

	var ltFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactLaunchTemplateInstanceProfile {
			ltFacts = append(ltFacts, f)
		}
	}

	require.Len(t, ltFacts, 1)
	assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:launch-template/lt-abc123", ltFacts[0].ResourceARN)
	assert.Equal(t, "AWS::EC2::LaunchTemplate", ltFacts[0].ResourceType)
	// For launch templates, the "role" is the instance profile reference (ARN or name).
	assert.Equal(t, "arn:aws:iam::123456789012:instance-profile/prod-profile", ltFacts[0].RoleARN)
	assert.Equal(t, "123456789012", ltFacts[0].AccountID)
	assert.Equal(t, "us-west-2", ltFacts[0].Region)
}

func TestCollectLaunchTemplateInstanceProfileNameForm(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:ec2:us-east-1:123456789012:launch-template/lt-def456", output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ResourceID:   "lt-def456",
		ARN:          "arn:aws:ec2:us-east-1:123456789012:launch-template/lt-def456",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"IamInstanceProfile": "prod-profile",
		},
	})

	facts := Collect(resources)

	var ltFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactLaunchTemplateInstanceProfile {
			ltFacts = append(ltFacts, f)
		}
	}

	require.Len(t, ltFacts, 1)
	assert.Equal(t, "prod-profile", ltFacts[0].RoleARN)
}

func TestCollectLaunchTemplateNoProfile(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:ec2:us-east-1:123456789012:launch-template/lt-noprofile", output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ResourceID:   "lt-noprofile",
		ARN:          "arn:aws:ec2:us-east-1:123456789012:launch-template/lt-noprofile",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"IamInstanceProfile": "",
		},
	})

	facts := Collect(resources)

	for _, f := range facts {
		if f.FactType == FactLaunchTemplateInstanceProfile {
			t.Errorf("expected no launch_template_instance_profile fact for profileless template, got %+v", f)
		}
	}
}

func TestCollectCloudFormationStackRole(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid", output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ResourceID:   "my-stack",
		ARN:          "arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"RoleARN": "arn:aws:iam::123456789012:role/cfn-service-role",
		},
	})

	facts := Collect(resources)

	var cfnFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactCloudFormationStackRole {
			cfnFacts = append(cfnFacts, f)
		}
	}

	require.Len(t, cfnFacts, 1)
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid", cfnFacts[0].ResourceARN)
	assert.Equal(t, "AWS::CloudFormation::Stack", cfnFacts[0].ResourceType)
	assert.Equal(t, "arn:aws:iam::123456789012:role/cfn-service-role", cfnFacts[0].RoleARN)
	assert.Equal(t, "123456789012", cfnFacts[0].AccountID)
	assert.Equal(t, "us-east-1", cfnFacts[0].Region)
}

func TestCollectCloudFormationStackNoRole(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	resources.Set("arn:aws:cloudformation:us-east-1:123456789012:stack/roleless/guid", output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ResourceID:   "roleless",
		ARN:          "arn:aws:cloudformation:us-east-1:123456789012:stack/roleless/guid",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties: map[string]any{
			"RoleARN": "",
		},
	})

	facts := Collect(resources)

	for _, f := range facts {
		if f.FactType == FactCloudFormationStackRole {
			t.Errorf("expected no cloudformation_stack_role fact for roleless stack, got %+v", f)
		}
	}
}

func TestCollectMultipleFactTypes(t *testing.T) {
	// A resource map with one of each priority type produces exactly 3 facts.
	resources := store.NewMap[output.AWSResource]()
	resources.Set("cb", output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ARN:          "arn:aws:codebuild:us-east-1:111:project/p",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"ServiceRole": "arn:aws:iam::111:role/cb-role"},
	})
	resources.Set("lt", output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ARN:          "arn:aws:ec2:us-east-1:111:launch-template/lt-1",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"IamInstanceProfile": "arn:aws:iam::111:instance-profile/ip"},
	})
	resources.Set("cfn", output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ARN:          "arn:aws:cloudformation:us-east-1:111:stack/s/g",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"RoleARN": "arn:aws:iam::111:role/cfn-role"},
	})

	facts := Collect(resources)

	typeCount := map[string]int{}
	for _, f := range facts {
		typeCount[f.FactType]++
	}
	assert.Equal(t, 1, typeCount[FactCodeBuildServiceRole])
	assert.Equal(t, 1, typeCount[FactLaunchTemplateInstanceProfile])
	assert.Equal(t, 1, typeCount[FactCloudFormationStackRole])
}

func TestCollectAllFactTypes(t *testing.T) {
	// Verify every supported fact type emits when its resource has a role reference.
	resources := store.NewMap[output.AWSResource]()

	addResource := func(key, resourceType, arn, accountRef, region string, props map[string]any) {
		resources.Set(key, output.AWSResource{
			ResourceType: resourceType,
			ARN:          arn,
			AccountRef:   accountRef,
			Region:       region,
			Properties:   props,
		})
	}

	addResource("lambda", "AWS::Lambda::Function",
		"arn:aws:lambda:us-east-1:111:function:fn", "111", "us-east-1",
		map[string]any{"Role": "arn:aws:iam::111:role/lambda-exec"})

	addResource("ecs-td", "AWS::ECS::TaskDefinition",
		"arn:aws:ecs:us-east-1:111:task-definition/td:1", "111", "us-east-1",
		map[string]any{"TaskRoleArn": "arn:aws:iam::111:role/ecs-task"})

	addResource("glue-job", "AWS::Glue::Job",
		"arn:aws:glue:us-east-1:111:job/j", "111", "us-east-1",
		map[string]any{"Role": "arn:aws:iam::111:role/glue-job"})

	addResource("glue-ep", "AWS::Glue::DevEndpoint",
		"arn:aws:glue:us-east-1:111:devEndpoint/de", "111", "us-east-1",
		map[string]any{"RoleArn": "arn:aws:iam::111:role/glue-ep"})

	addResource("apprunner", "AWS::AppRunner::Service",
		"arn:aws:apprunner:us-east-1:111:service/ar", "111", "us-east-1",
		map[string]any{"InstanceRoleArn": "arn:aws:iam::111:role/apprunner"})

	addResource("sfn", "AWS::StepFunctions::StateMachine",
		"arn:aws:states:us-east-1:111:stateMachine/sm", "111", "us-east-1",
		map[string]any{"RoleArn": "arn:aws:iam::111:role/sfn-exec"})

	addResource("sm-nb", "AWS::SageMaker::NotebookInstance",
		"arn:aws:sagemaker:us-east-1:111:notebook-instance/nb", "111", "us-east-1",
		map[string]any{"RoleArn": "arn:aws:iam::111:role/sm-exec"})

	addResource("batch", "AWS::Batch::JobDefinition",
		"arn:aws:batch:us-east-1:111:job-definition/jd:1", "111", "us-east-1",
		map[string]any{"JobRoleArn": "arn:aws:iam::111:role/batch-job"})

	addResource("bedrock", "AWS::BedrockAgentCore::CodeInterpreter",
		"arn:aws:bedrock-agentcore:us-east-1:111:code-interpreter/ci", "111", "us-east-1",
		map[string]any{"ExecutionRoleArn": "arn:aws:iam::111:role/bedrock-exec"})

	addResource("ec2", "AWS::EC2::Instance",
		"arn:aws:ec2:us-east-1:111:instance/i-1", "111", "us-east-1",
		map[string]any{"IamInstanceProfile": "arn:aws:iam::111:instance-profile/ec2-ip"})

	addResource("cognito", "AWS::Cognito::IdentityPool",
		"arn:aws:cognito-identity:us-east-1:111:identitypool/us-east-1:pool-1", "111", "us-east-1",
		map[string]any{"authenticatedRole": "arn:aws:iam::111:role/cognito-auth"})

	facts := Collect(resources)

	typeCount := map[string]int{}
	for _, f := range facts {
		typeCount[f.FactType]++
	}

	assert.Equal(t, 1, typeCount[FactLambdaExecutionRole], "lambda_execution_role")
	assert.Equal(t, 1, typeCount[FactECSTaskRole], "ecs_task_role")
	assert.Equal(t, 1, typeCount[FactGlueJobRole], "glue_job_role")
	assert.Equal(t, 1, typeCount[FactGlueEndpointRole], "glue_endpoint_role")
	assert.Equal(t, 1, typeCount[FactAppRunnerServiceRole], "apprunner_service_role")
	assert.Equal(t, 1, typeCount[FactStepFunctionsRole], "stepfunctions_role")
	assert.Equal(t, 1, typeCount[FactSageMakerNotebookRole], "sagemaker_notebook_role")
	assert.Equal(t, 1, typeCount[FactBatchJobRole], "batch_job_role")
	assert.Equal(t, 1, typeCount[FactBedrockInterpreterRole], "bedrock_interpreter_role")
	assert.Equal(t, 1, typeCount[FactInstanceProfile], "instance_profile")
	assert.Equal(t, 1, typeCount[FactCognitoPoolRole], "cognito_pool_role")
}

func TestCollectNilProperties(t *testing.T) {
	// A resource with nil Properties must not panic.
	resources := store.NewMap[output.AWSResource]()
	resources.Set("cb", output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ARN:          "arn:aws:codebuild:us-east-1:111:project/p",
		AccountRef:   "111",
	})

	facts := Collect(resources)

	for _, f := range facts {
		if f.FactType == FactCodeBuildServiceRole {
			t.Errorf("expected no fact for nil-properties resource, got %+v", f)
		}
	}
}

func TestCollectEmptyResources(t *testing.T) {
	resources := store.NewMap[output.AWSResource]()
	facts := Collect(resources)
	assert.Empty(t, facts)
}

func TestCollectBatchJobDefinition(t *testing.T) {
	// A Batch job definition emits a fact only for JobRoleArn (the container
	// role). ExecutionRoleArn is the infrastructure role and not attacker-accessible.
	resources := store.NewMap[output.AWSResource]()
	resources.Set("batch", output.AWSResource{
		ResourceType: "AWS::Batch::JobDefinition",
		ARN:          "arn:aws:batch:us-east-1:111:job-definition/jd:1",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties: map[string]any{
			"JobRoleArn":       "arn:aws:iam::111:role/batch-job",
			"ExecutionRoleArn": "arn:aws:iam::111:role/batch-exec",
		},
	})

	facts := Collect(resources)

	var batchFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactBatchJobRole {
			batchFacts = append(batchFacts, f)
		}
	}

	// Only JobRoleArn emits a fact; ExecutionRoleArn is ignored.
	require.Len(t, batchFacts, 1)
	assert.Equal(t, "arn:aws:iam::111:role/batch-job", batchFacts[0].RoleARN)
}

func TestCollectCognitoMultipleRoles(t *testing.T) {
	// A Cognito identity pool with both auth and unauth roles emits two facts.
	resources := store.NewMap[output.AWSResource]()
	resources.Set("cognito", output.AWSResource{
		ResourceType: "AWS::Cognito::IdentityPool",
		ARN:          "arn:aws:cognito-identity:us-east-1:111:identitypool/us-east-1:pool-1",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties: map[string]any{
			"authenticatedRole":   "arn:aws:iam::111:role/cognito-auth",
			"unauthenticatedRole": "arn:aws:iam::111:role/cognito-unauth",
		},
	})

	facts := Collect(resources)

	var cognitoFacts []output.StructuralFact
	for _, f := range facts {
		if f.FactType == FactCognitoPoolRole {
			cognitoFacts = append(cognitoFacts, f)
		}
	}

	require.Len(t, cognitoFacts, 2)
	roles := map[string]bool{}
	for _, f := range cognitoFacts {
		roles[f.RoleARN] = true
	}
	assert.True(t, roles["arn:aws:iam::111:role/cognito-auth"])
	assert.True(t, roles["arn:aws:iam::111:role/cognito-unauth"])
}
