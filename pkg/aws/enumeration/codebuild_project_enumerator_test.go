package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildCodeBuildProjectResource(t *testing.T) {
	project := codebuildtypes.Project{
		Name:        aws.String("build-proj"),
		Arn:         aws.String("arn:aws:codebuild:us-east-2:123456789012:project/build-proj"),
		ServiceRole: aws.String("arn:aws:iam::123456789012:role/codebuild-service-role"),
	}

	r := buildCodeBuildProjectResource(project, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::CodeBuild::Project", r.ResourceType)
	assert.Equal(t, "build-proj", r.ResourceID)
	assert.Equal(t, "arn:aws:codebuild:us-east-2:123456789012:project/build-proj", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// ServiceRole must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/codebuild-service-role", r.Properties["ServiceRole"])
	// Projects carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildCodeBuildProjectResourceNoRole(t *testing.T) {
	// A roleless project emits an empty ServiceRole — fail-closed: no ARN to match, no edge.
	project := codebuildtypes.Project{
		Name: aws.String("roleless"),
		Arn:  aws.String("arn:aws:codebuild:us-west-2:123456789012:project/roleless"),
	}

	r := buildCodeBuildProjectResource(project, "123456789012", "us-west-2")

	assert.Equal(t, "roleless", r.ResourceID)
	assert.Equal(t, "", r.Properties["ServiceRole"])
}

func TestBuildCodeBuildProjectResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	project := codebuildtypes.Project{
		Name: aws.String("no-arn"),
	}

	r := buildCodeBuildProjectResource(project, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:codebuild:eu-west-1:123456789012:project/no-arn", r.ARN)
	assert.Equal(t, "no-arn", r.ResourceID)
	assert.Equal(t, "", r.Properties["ServiceRole"])
}

func TestChunkStrings(t *testing.T) {
	assert.Equal(t, [][]string{{"a", "b"}, {"c"}}, chunkStrings([]string{"a", "b", "c"}, 2))
	assert.Equal(t, [][]string{{"a", "b", "c"}}, chunkStrings([]string{"a", "b", "c"}, 3))
	assert.Equal(t, [][]string{{"a", "b", "c"}}, chunkStrings([]string{"a", "b", "c"}, 10))
	assert.Nil(t, chunkStrings(nil, 2))
	assert.Empty(t, chunkStrings([]string{}, 2))
}
