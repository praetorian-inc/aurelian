package llm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AnthropicLLMAnalyzer is a generic link for analyzing content using Anthropic's Claude API.
// It works with any content that implements the AnalyzableContent interface.
type AnthropicLLMAnalyzer struct {
	*chain.Base
	apiKey     string
	model      string
	basePrompt string
	maxTokens  int
	client     *http.Client
}

// AnthropicRequest represents the request structure for Anthropic's API
type AnthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type Message struct {
	Role    string    `json:"role"`
	Content []Content `json:"content"`
}

type Content struct {
	Type   string       `json:"type"`
	Text   string       `json:"text,omitempty"`
	Source *ImageSource `json:"source,omitempty"`
}

type ImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

// AnthropicResponse represents the response structure from Anthropic's API
type AnthropicResponse struct {
	Content []ResponseContent `json:"content"`
	Usage   Usage            `json:"usage"`
}

type ResponseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func NewAnthropicLLMAnalyzer(configs ...cfg.Config) chain.Link {
	analyzer := &AnthropicLLMAnalyzer{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
	analyzer.Base = chain.NewBase(analyzer, configs...)
	return analyzer
}

func (a *AnthropicLLMAnalyzer) Initialize() error {
	// Get API key from configuration
	apiKey, err := cfg.As[string](a.Arg("anthropic-api-key"))
	if err != nil || apiKey == "" {
		slog.Info("Anthropic API key not provided, skipping LLM analysis")
		a.apiKey = ""
		return nil
	}
	a.apiKey = apiKey

	// Get model configuration
	model, err := cfg.As[string](a.Arg("anthropic-model"))
	if err != nil {
		model = "claude-3-7-sonnet-latest" // Default model
	}
	a.model = model

	// Get analysis prompt
	prompt, err := cfg.As[string](a.Arg("analysis-prompt"))
	if err != nil || prompt == "" {
		slog.Debug("Failed to get analysis-prompt parameter or empty prompt, using generic default", "error", err, "prompt_empty", prompt == "")
		prompt = a.getDefaultGenericPrompt() // Generic default
	} else {
		slog.Debug("Successfully loaded analysis prompt", "prompt_length", len(prompt))
	}
	a.basePrompt = prompt

	// Get max tokens
	maxTokens, err := cfg.As[int](a.Arg("max-tokens"))
	if err != nil {
		maxTokens = 1000 // Default
	}
	a.maxTokens = maxTokens

	slog.Debug("Initialized Anthropic LLM analyzer",
		"model", a.model,
		"max_tokens", a.maxTokens,
		"api_key_available", a.apiKey != "",
		"prompt_set", a.basePrompt != "",
		"prompt_length", len(a.basePrompt))

	return nil
}

func (a *AnthropicLLMAnalyzer) Process(input any) error {
	// Check if input implements AnalyzableContent interface
	analyzable, ok := input.(types.AnalyzableContent)
	if !ok {
		slog.Debug("Input does not implement AnalyzableContent interface, passing through unchanged",
			"input_type", fmt.Sprintf("%T", input))
		a.Send(input)
		return nil
	}

	// Skip analysis if no API key available
	if a.apiKey == "" {
		slog.Debug("No Anthropic API key available, passing through without analysis")
		a.Send(input)
		return nil
	}

	// Get the data to analyze
	data := analyzable.GetAnalyzableData()
	if len(data) == 0 {
		slog.Debug("No analyzable data found, passing through without analysis")
		a.Send(input)
		return nil
	}

	slog.Info("Starting LLM analysis",
		"model", a.model,
		"data_size_bytes", len(data))

	startTime := time.Now()

	// Perform the analysis
	result, err := a.analyzeContent(data, analyzable)
	if err != nil {
		slog.Error("LLM analysis failed, passing through original content",
			"error", err)
		a.Send(input)
		return nil // Don't fail the chain
	}

	result.AnalysisDuration = time.Since(startTime).Milliseconds()

	// Set the analysis result on the input
	analyzable.SetAnalysisResult(*result)

	slog.Info("LLM analysis completed successfully",
		"sensitive_info_found", result.SensitiveInfoFound,
		"findings_count", len(result.Findings),
		"confidence_score", result.ConfidenceScore,
		"duration_ms", result.AnalysisDuration)

	// Send the enriched content to the next link
	a.Send(input)
	return nil
}

// analyzeContent sends the data to Anthropic's API for analysis
func (a *AnthropicLLMAnalyzer) analyzeContent(data []byte, analyzable types.AnalyzableContent) (*types.LLMAnalysisResult, error) {
	// Validate that we have a prompt
	if a.basePrompt == "" {
		return nil, fmt.Errorf("analysis prompt is empty")
	}

	// Build content array based on content type from interface
	var content []Content

	switch analyzable.GetContentType() {
	case types.ContentTypeImage:
		// Encode the image data as base64 for the API
		encodedData := base64.StdEncoding.EncodeToString(data)
		if encodedData == "" {
			return nil, fmt.Errorf("failed to encode image data")
		}

		// Add image first (recommended for best performance)
		content = append(content, Content{
			Type: "image",
			Source: &ImageSource{
				Type:      "base64",
				MediaType: analyzable.GetMediaType(),
				Data:      encodedData,
			},
		})

		// Add text prompt after image
		content = append(content, Content{
			Type: "text",
			Text: a.basePrompt,
		})

	case types.ContentTypeText:
		// For text content, combine prompt with the text to analyze
		textContent := string(data)
		promptWithContent := fmt.Sprintf("%s\n\nContent to analyze:\n%s", a.basePrompt, textContent)

		content = append(content, Content{
			Type: "text",
			Text: promptWithContent,
		})

	default:
		return nil, fmt.Errorf("unsupported content type: %s", analyzable.GetContentType())
	}

	// Build the request
	request := AnthropicRequest{
		Model:     a.model,
		MaxTokens: a.maxTokens,
		Messages: []Message{
			{
				Role:    "user",
				Content: content,
			},
		},
	}

	// Marshal request to JSON
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Debug log the request (remove sensitive data)
	contentTypes := make([]string, len(request.Messages[0].Content))
	for i, c := range request.Messages[0].Content {
		contentTypes[i] = c.Type
	}

	slog.Debug("Anthropic API request structure",
		"model", request.Model,
		"max_tokens", request.MaxTokens,
		"content_items", len(request.Messages[0].Content),
		"content_types", contentTypes)

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// Send the request
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for API errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Parse the response
	var apiResponse AnthropicResponse
	if err := json.Unmarshal(responseBody, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(apiResponse.Content) == 0 {
		return nil, fmt.Errorf("no content in API response")
	}

	// Parse the analysis results from the response text
	analysisText := apiResponse.Content[0].Text
	result, err := a.parseAnalysisResponse(analysisText)
	if err != nil {
		return nil, fmt.Errorf("failed to parse analysis response: %w", err)
	}

	// Add metadata
	result.AnalysisTimestamp = time.Now()
	result.Model = a.model
	result.PromptUsed = a.basePrompt
	result.TokensUsed = apiResponse.Usage.InputTokens + apiResponse.Usage.OutputTokens

	return result, nil
}

// parseAnalysisResponse attempts to parse structured analysis results from the LLM response
func (a *AnthropicLLMAnalyzer) parseAnalysisResponse(response string) (*types.LLMAnalysisResult, error) {
	// Extract JSON from markdown code blocks if present
	jsonStr := response
	if strings.Contains(response, "```json") {
		// Find the JSON block between ```json and ```
		start := strings.Index(response, "```json")
		if start != -1 {
			start += 7 // Move past ```json
			end := strings.Index(response[start:], "```")
			if end != -1 {
				jsonStr = strings.TrimSpace(response[start : start+end])
			}
		}
	} else if strings.Contains(response, "```") {
		// Try generic code block extraction
		start := strings.Index(response, "```")
		if start != -1 {
			start += 3
			end := strings.Index(response[start:], "```")
			if end != -1 {
				jsonStr = strings.TrimSpace(response[start : start+end])
			}
		}
	}

	// Try to parse as JSON first (if the LLM returned structured data)
	var structuredResult types.LLMAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &structuredResult); err == nil {
		return &structuredResult, nil
	}

	// Fall back to text analysis
	result := &types.LLMAnalysisResult{
		SensitiveInfoFound: false,
		ConfidenceScore:    0.0,
		Summary:            response,
		Findings:           []types.SensitiveFinding{},
	}

	// Simple heuristic analysis of the text response
	lowerResponse := strings.ToLower(response)
	sensitiveKeywords := []string{
		"password", "credential", "api key", "secret", "token",
		"sensitive", "confidential", "private key", "ssh key",
		"access key", "database", "login", "username",
	}

	// Keywords to exclude (not considered sensitive on their own)
	excludeKeywords := []string{
		"ip address", "network", "vpc", "subnet", "cidr",
	}

	// Check if response contains any exclude keywords (don't flag as sensitive)
	hasExcludedContent := false
	for _, excludeKeyword := range excludeKeywords {
		if strings.Contains(lowerResponse, excludeKeyword) {
			hasExcludedContent = true
			break
		}
	}

	foundKeywords := make(map[string]bool)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerResponse, keyword) {
			// Only flag as sensitive if not purely about excluded content
			if !hasExcludedContent {
				foundKeywords[keyword] = true
				result.SensitiveInfoFound = true
			}
		}
	}

	// Create findings based on detected keywords
	for keyword := range foundKeywords {
		finding := types.SensitiveFinding{
			Type:        "potential_" + strings.ReplaceAll(keyword, " ", "_"),
			Description: fmt.Sprintf("Potential %s detected in content", keyword),
			Confidence:  0.7, // Moderate confidence for keyword detection
			Location:    "detected_in_analysis",
			Severity:    "medium",
		}
		result.Findings = append(result.Findings, finding)
	}

	// Set overall confidence based on findings
	if len(result.Findings) > 0 {
		result.ConfidenceScore = 0.7
	}

	return result, nil
}

// getDefaultGenericPrompt returns a generic prompt for content analysis
func (a *AnthropicLLMAnalyzer) getDefaultGenericPrompt() string {
	return `Please analyze this content (image or text) for any sensitive information that should not be exposed. Look for:

1. **Credentials & Authentication**:
   - Passwords, passphrases, or authentication tokens
   - API keys, access keys, or service credentials
   - Database connection strings or authentication details
   - SSH keys, certificates, or cryptographic material

2. **Personal & Sensitive Data**:
   - Personal Identifiable Information (PII)
   - Financial information or payment details
   - Internal contact information or employee data

3. **System & Infrastructure**:
   - Internal system information, IP addresses, or network details
   - Configuration files or environment variables with secrets
   - Service endpoints or internal URLs

Respond with a JSON object containing:
{
  "sensitive_info_found": boolean,
  "confidence_score": float (0.0-1.0),
  "summary": "brief description of findings or 'No sensitive information detected'",
  "findings": [
    {
      "type": "credential|api_key|password|secret|pii|financial|system_info",
      "description": "detailed description of what was found",
      "confidence": float (0.0-1.0),
      "location": "description of where it appears",
      "severity": "low|medium|high|critical"
    }
  ]
}

If no sensitive information is detected, respond with "sensitive_info_found": false and provide a brief summary.`
}

func (a *AnthropicLLMAnalyzer) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("anthropic-api-key", "Anthropic API key for Claude analysis").WithDefault(""),
		cfg.NewParam[string]("anthropic-model", "Anthropic model to use").WithDefault("claude-3-7-sonnet-latest"),
		cfg.NewParam[string]("analysis-prompt", "Custom prompt for content analysis"),
		cfg.NewParam[int]("max-tokens", "Maximum tokens for LLM response").WithDefault(1000),
	}
}

func (a *AnthropicLLMAnalyzer) Metadata() *cfg.Metadata {
	return &cfg.Metadata{
		Name: "Anthropic LLM Analyzer",
	}
}
