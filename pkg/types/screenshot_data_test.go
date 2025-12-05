package types

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScreenshotData_AnalyzableContent(t *testing.T) {
	// Create test data
	imageData := []byte("fake-png-data")
	resource := &EnrichedResourceDescription{
		Identifier: "i-1234567890abcdef0",
		TypeName:   "AWS::EC2::Instance",
		Region:     "us-east-1",
		AccountId:  "123456789012",
		Arn: arn.ARN{
			Partition: "aws",
			Service:   "ec2",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Resource:  "instance/i-1234567890abcdef0",
		},
	}

	// Create ScreenshotData
	screenshot := NewScreenshotData(resource, imageData)

	t.Run("implements AnalyzableContent interface", func(t *testing.T) {
		// Test interface compliance
		var _ AnalyzableContent = screenshot

		// Test GetAnalyzableData
		data := screenshot.GetAnalyzableData()
		assert.Equal(t, imageData, data)
	})

	t.Run("has correct initial state", func(t *testing.T) {
		assert.Equal(t, "i-1234567890abcdef0", screenshot.InstanceID)
		assert.Equal(t, "us-east-1", screenshot.Region)
		assert.Equal(t, "123456789012", screenshot.AccountID)
		assert.Equal(t, "png", screenshot.Format)
		assert.False(t, screenshot.HasAnalysis())
		assert.Nil(t, screenshot.GetAnalysisResult())
	})

	t.Run("can set and get analysis results", func(t *testing.T) {
		analysis := LLMAnalysisResult{
			SensitiveInfoFound: true,
			ConfidenceScore:    0.85,
			Summary:           "Test analysis",
			Findings: []SensitiveFinding{
				{
					Type:        "credential",
					Description: "Potential password found",
					Confidence:  0.9,
					Location:    "center",
					Severity:    "high",
				},
			},
			AnalysisTimestamp: time.Now(),
			Model:            "claude-3-sonnet-20240229",
		}

		screenshot.SetAnalysisResult(analysis)

		assert.True(t, screenshot.HasAnalysis())
		result := screenshot.GetAnalysisResult()
		require.NotNil(t, result)
		assert.Equal(t, analysis.SensitiveInfoFound, result.SensitiveInfoFound)
		assert.Equal(t, analysis.ConfidenceScore, result.ConfidenceScore)
		assert.Len(t, result.Findings, 1)
	})

	t.Run("generates correct filename", func(t *testing.T) {
		filename := screenshot.GetFilename()
		assert.True(t, strings.HasPrefix(filename, "123456789012-ec2-screenshot-i-1234567890abcdef0-"))
		assert.True(t, strings.HasSuffix(filename, ".png"))
	})

	t.Run("generates correct directory", func(t *testing.T) {
		directory := screenshot.GetDirectory()
		assert.Equal(t, "ec2-console-screenshots", directory)
	})
}

func TestLLMAnalysisResult_HelperMethods(t *testing.T) {
	analysis := &LLMAnalysisResult{
		SensitiveInfoFound: true,
		ConfidenceScore:    0.75,
		Findings: []SensitiveFinding{
			{
				Type:       "password",
				Confidence: 0.9,
				Severity:   "critical",
			},
			{
				Type:       "api_key",
				Confidence: 0.6,
				Severity:   "high",
			},
			{
				Type:       "password",
				Confidence: 0.8,
				Severity:   "medium",
			},
		},
	}

	t.Run("HasHighConfidenceFindings", func(t *testing.T) {
		assert.True(t, analysis.HasHighConfidenceFindings(0.7))
		assert.True(t, analysis.HasHighConfidenceFindings(0.8))
		assert.False(t, analysis.HasHighConfidenceFindings(0.95))
	})

	t.Run("GetCriticalFindings", func(t *testing.T) {
		critical := analysis.GetCriticalFindings()
		assert.Len(t, critical, 1)
		assert.Equal(t, "password", critical[0].Type)
		assert.Equal(t, "critical", critical[0].Severity)
	})

	t.Run("GetFindingsByType", func(t *testing.T) {
		passwords := analysis.GetFindingsByType("password")
		assert.Len(t, passwords, 2)

		apiKeys := analysis.GetFindingsByType("api_key")
		assert.Len(t, apiKeys, 1)
		assert.Equal(t, "api_key", apiKeys[0].Type)

		notFound := analysis.GetFindingsByType("nonexistent")
		assert.Len(t, notFound, 0)
	})
}