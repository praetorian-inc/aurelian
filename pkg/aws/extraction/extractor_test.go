package extraction

import (
	"errors"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtract_UnknownTypeReturnsError(t *testing.T) {
	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{})
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
		"AWS::SSM::Parameter",
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

	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{})
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

func TestExtract_FailOnErrorRejectsPartialExtraction(t *testing.T) {
	mustRegister("AWS::UnitTest::StrictType", "fails", func(_ extractContext, _ output.AWSResource, _ *pipeline.P[output.ScanInput]) error {
		return errors.New("boom")
	})

	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{FailOnError: true})
	out := pipeline.New[output.ScanInput]()
	go func() {
		err := ex.Extract(output.AWSResource{ResourceType: "AWS::UnitTest::StrictType", ResourceID: "r1", Region: "us-east-1"}, out)
		out.CloseWithError(err)
	}()

	items, err := out.Collect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.Empty(t, items)
}

// An old LastModified only skips a resource when ModifiedSince is set.
// Guard's Match() gate filters by resource type alone, so without an explicit
// cutoff -- and under logs-since, which bounds log events rather than
// resources -- every resource is still extracted.
func TestExtract_OldLastModifiedResourceIsStillExtracted(t *testing.T) {
	mustRegister("AWS::UnitTest::OldResource", "emits", func(_ extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
		out.Send(output.ScanInput{ResourceID: r.ResourceID, Label: "old", Content: []byte("content")})
		return nil
	})

	modified := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "default config", cfg: Config{}},
		{name: "logs-since after last modified", cfg: Config{LogsSince: time.Date(2026, time.August, 24, 11, 0, 0, 0, time.UTC)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, tt.cfg)
			out := pipeline.New[output.ScanInput]()
			resource := output.AWSResource{
				ResourceType: "AWS::UnitTest::OldResource",
				ResourceID:   "resource-1",
				Region:       "us-east-1",
				LastModified: &modified,
			}
			go func() {
				out.CloseWithError(ex.Extract(resource, out))
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1)
			assert.Equal(t, "resource-1", items[0].ResourceID)
			assert.Equal(t, "old", items[0].Label)
		})
	}
}

func TestExtract_ECSPropertiesExtractor(t *testing.T) {
	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{})
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
	assert.Equal(t, "ECS Task Definition", items[0].Label)
}

// ModifiedSince skips a resource whose LastModified is at or before the
// cutoff, before any extractor or AWS config is built. The skip is
// resource-level and applies to every type, unlike logs-since.
func TestExtract_UnchangedResourceIsSkipped(t *testing.T) {
	modified := time.Date(2026, time.August, 24, 11, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		modifiedSince time.Time
		wantSkipped   bool
	}{
		{name: "cutoff after last modified", modifiedSince: modified.Add(time.Hour), wantSkipped: true},
		{name: "cutoff equal to last modified", modifiedSince: modified, wantSkipped: true},
		{name: "cutoff before last modified", modifiedSince: modified.Add(-time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{ModifiedSince: tt.modifiedSince})
			out := pipeline.New[output.ScanInput]()
			resource := output.AWSResource{
				ResourceType: "AWS::UnitTest::OldResource",
				ResourceID:   "resource-1",
				Region:       "us-east-1",
				LastModified: &modified,
			}
			go func() {
				out.CloseWithError(ex.Extract(resource, out))
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			if tt.wantSkipped {
				assert.Empty(t, items, "an unchanged resource must not be extracted")
				return
			}
			require.Len(t, items, 1)
			assert.Equal(t, "resource-1", items[0].ResourceID)
		})
	}
}

// A resource AWS gives no modification metadata for is always scanned: a nil
// LastModified must never be read as "older than the cutoff".
func TestExtract_NilLastModifiedIsNeverSkipped(t *testing.T) {
	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{
		ModifiedSince: time.Date(2026, time.August, 24, 11, 0, 0, 0, time.UTC),
	})
	out := pipeline.New[output.ScanInput]()
	go func() {
		out.CloseWithError(ex.Extract(output.AWSResource{
			ResourceType: "AWS::UnitTest::OldResource",
			ResourceID:   "resource-1",
			Region:       "us-east-1",
		}, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1, "a resource with no LastModified must always be extracted")
}
