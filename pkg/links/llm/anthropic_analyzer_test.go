package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Mock implementations for testing
type mockImageContent struct {
	data      []byte
	mediaType string
}

func (m *mockImageContent) GetAnalyzableData() []byte               { return m.data }
func (m *mockImageContent) GetContentType() types.ContentType      { return types.ContentTypeImage }
func (m *mockImageContent) GetMediaType() string                   { return m.mediaType }
func (m *mockImageContent) SetAnalysisResult(types.LLMAnalysisResult) {}
func (m *mockImageContent) GetAnalysisResult() *types.LLMAnalysisResult { return nil }

type mockTextContent struct {
	data []byte
}

func (m *mockTextContent) GetAnalyzableData() []byte               { return m.data }
func (m *mockTextContent) GetContentType() types.ContentType      { return types.ContentTypeText }
func (m *mockTextContent) GetMediaType() string                   { return "text/plain" }
func (m *mockTextContent) SetAnalysisResult(types.LLMAnalysisResult) {}
func (m *mockTextContent) GetAnalysisResult() *types.LLMAnalysisResult { return nil }

func TestAnthropicLLMAnalyzer_ContentTypeHandling(t *testing.T) {
	t.Run("handles image content", func(t *testing.T) {
		imageContent := &mockImageContent{
			data:      []byte("fake-image-data"),
			mediaType: "image/png",
		}

		assert.Equal(t, types.ContentTypeImage, imageContent.GetContentType())
		assert.Equal(t, "image/png", imageContent.GetMediaType())
	})

	t.Run("handles text content", func(t *testing.T) {
		textContent := &mockTextContent{
			data: []byte("Some text to analyze"),
		}

		assert.Equal(t, types.ContentTypeText, textContent.GetContentType())
		assert.Equal(t, "text/plain", textContent.GetMediaType())
	})
}

func TestAnthropicLLMAnalyzer_PromptGeneration(t *testing.T) {
	analyzer := &AnthropicLLMAnalyzer{}

	t.Run("returns generic prompt", func(t *testing.T) {
		prompt := analyzer.getDefaultGenericPrompt()
		assert.Contains(t, prompt, "sensitive information")
		assert.Contains(t, prompt, "JSON object")
		assert.Contains(t, prompt, "image or text")
	})
}