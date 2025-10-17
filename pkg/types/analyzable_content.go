package types

import "time"

// AnalyzableContent is a generic interface for content that can be analyzed by LLM links.
// This enables reusable LLM analysis across different content types (screenshots, documents, etc.)
type AnalyzableContent interface {
	// GetAnalyzableData returns the raw data to be analyzed (image bytes, text, etc.)
	GetAnalyzableData() []byte

	// GetContentType returns the type of content for proper API handling
	GetContentType() ContentType

	// GetMediaType returns the media type (for images: "image/png", "image/jpeg", etc.)
	GetMediaType() string

	// SetAnalysisResult stores the analysis results from the LLM
	SetAnalysisResult(result LLMAnalysisResult)

	// GetAnalysisResult retrieves the analysis results if available
	GetAnalysisResult() *LLMAnalysisResult
}

// ContentType represents the type of content being analyzed
type ContentType string

const (
	ContentTypeImage ContentType = "image"
	ContentTypeText  ContentType = "text"
)

// LLMAnalysisResult contains the results of LLM-based content analysis
type LLMAnalysisResult struct {
	// Overall analysis results
	SensitiveInfoFound bool    `json:"sensitive_info_found"`
	ConfidenceScore    float64 `json:"confidence_score"` // 0.0 to 1.0
	Summary            string  `json:"summary"`

	// Individual findings
	Findings []SensitiveFinding `json:"findings"`

	// Analysis metadata
	AnalysisTimestamp time.Time `json:"analysis_timestamp"`
	Model             string    `json:"model"`       // e.g., "claude-3-sonnet-20240229"
	PromptUsed        string    `json:"prompt_used"` // The prompt template used
	TokensUsed        int       `json:"tokens_used,omitempty"`
	AnalysisDuration  int64     `json:"analysis_duration_ms,omitempty"` // milliseconds
}

// SensitiveFinding represents a specific sensitive information detection
type SensitiveFinding struct {
	// Type of sensitive information detected
	Type string `json:"type"` // e.g., "credential", "pii", "api_key", "password", "secret"

	// Human-readable description
	Description string `json:"description"`

	// Confidence level for this specific finding (0.0 to 1.0)
	Confidence float64 `json:"confidence"`

	// Location information (coordinates for images, line numbers for text, etc.)
	Location string `json:"location"`

	// Severity level
	Severity string `json:"severity"` // "low", "medium", "high", "critical"

	// Additional context or details
	Context string `json:"context,omitempty"`
}

// HasHighConfidenceFindings returns true if any findings exceed the confidence threshold
func (r *LLMAnalysisResult) HasHighConfidenceFindings(threshold float64) bool {
	if threshold <= 0 {
		threshold = 0.7 // Default threshold
	}

	for _, finding := range r.Findings {
		if finding.Confidence >= threshold {
			return true
		}
	}
	return false
}

// GetCriticalFindings returns findings marked as critical severity
func (r *LLMAnalysisResult) GetCriticalFindings() []SensitiveFinding {
	var critical []SensitiveFinding
	for _, finding := range r.Findings {
		if finding.Severity == "critical" {
			critical = append(critical, finding)
		}
	}
	return critical
}

// GetFindingsByType returns all findings of a specific type
func (r *LLMAnalysisResult) GetFindingsByType(findingType string) []SensitiveFinding {
	var matches []SensitiveFinding
	for _, finding := range r.Findings {
		if finding.Type == findingType {
			matches = append(matches, finding)
		}
	}
	return matches
}