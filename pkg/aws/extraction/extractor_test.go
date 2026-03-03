package extraction

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtract_UnknownTypeReturnsError(t *testing.T) {
	ex := NewAWSExtractor(plugin.AWSCommonRecon{}, Config{}, 1)
	out := pipeline.New[output.ScanInput]()
	err := ex.Extract(output.AWSResource{ResourceType: "AWS::S3::Bucket"}, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no extractor registered")
}

func TestExtract_AllSupportedResourceTypesRegistered(t *testing.T) {
	supportedTypes := []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
	}

	for _, rt := range supportedTypes {
		extractors := getExtractors(rt)
		require.NotEmpty(t, extractors, "no extractors registered for %s", rt)
	}
}

func TestExtract_FirstExtractorFailsSecondSucceeds(t *testing.T) {
	mustRegister("AWS::UnitTest::Type", "fails", func(_ extractContext, _ output.AWSResource, _ *pipeline.P[output.ScanInput]) error {
		return errors.New("boom")
	})
	mustRegister("AWS::UnitTest::Type", "works", func(_ extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
		out.Send(output.ScanInput{ResourceID: r.ResourceID, Label: "ok", Content: []byte("content")})
		return nil
	})

	ex := NewAWSExtractor(plugin.AWSCommonRecon{}, Config{}, 1)
	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		err := ex.Extract(output.AWSResource{ResourceType: "AWS::UnitTest::Type", ResourceID: "r1", Region: "us-east-1"}, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "ok", items[0].Label)
}

func TestExtract_ECSPropertiesExtractor(t *testing.T) {
	ex := NewAWSExtractor(plugin.AWSCommonRecon{}, Config{}, 1)
	out := pipeline.New[output.ScanInput]()
	resource := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"Family": "my-task",
		},
	}

	go func() {
		defer out.Close()
		err := ex.Extract(resource, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.NotEmpty(t, items)
	assert.Equal(t, "TaskDefinition", items[0].Label)
}
