package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/stretchr/testify/assert"
)

func TestBuildSageMakerNotebookInstanceResource(t *testing.T) {
	detail := &sagemaker.DescribeNotebookInstanceOutput{
		NotebookInstanceName: aws.String("ds-notebook"),
		NotebookInstanceArn:  aws.String("arn:aws:sagemaker:us-east-2:123456789012:notebook-instance/ds-notebook"),
		RoleArn:              aws.String("arn:aws:iam::123456789012:role/sagemaker-exec-role"),
	}

	r := buildSageMakerNotebookInstanceResource(detail, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::SageMaker::NotebookInstance", r.ResourceType)
	assert.Equal(t, "ds-notebook", r.ResourceID)
	assert.Equal(t, "arn:aws:sagemaker:us-east-2:123456789012:notebook-instance/ds-notebook", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// RoleArn must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/sagemaker-exec-role", r.Properties["RoleArn"])
	// Notebook instances carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildSageMakerNotebookInstanceResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	detail := &sagemaker.DescribeNotebookInstanceOutput{
		NotebookInstanceName: aws.String("no-arn-nb"),
		RoleArn:              aws.String("arn:aws:iam::123456789012:role/sagemaker-exec-role"),
	}

	r := buildSageMakerNotebookInstanceResource(detail, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:sagemaker:eu-west-1:123456789012:notebook-instance/no-arn-nb", r.ARN)
	assert.Equal(t, "no-arn-nb", r.ResourceID)
	assert.Equal(t, "arn:aws:iam::123456789012:role/sagemaker-exec-role", r.Properties["RoleArn"])
}

func TestBuildSageMakerNotebookInstanceResourceNilRole(t *testing.T) {
	// A nil RoleArn must not panic and emits an empty value (fail-closed).
	detail := &sagemaker.DescribeNotebookInstanceOutput{
		NotebookInstanceName: aws.String("no-role-nb"),
		NotebookInstanceArn:  aws.String("arn:aws:sagemaker:us-west-2:123456789012:notebook-instance/no-role-nb"),
	}

	r := buildSageMakerNotebookInstanceResource(detail, "123456789012", "us-west-2")

	assert.Equal(t, "", r.Properties["RoleArn"])
}
