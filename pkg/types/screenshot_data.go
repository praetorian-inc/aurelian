package types

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// ScreenshotData represents EC2 console screenshot data that flows through the analysis chain.
// It implements the AnalyzableContent interface to enable generic LLM processing.
type ScreenshotData struct {
	// Instance metadata (from EnrichedResourceDescription)
	InstanceID string  `json:"instance_id"`
	Region     string  `json:"region"`
	AccountID  string  `json:"account_id"`
	ARN        arn.ARN `json:"arn"`

	// Screenshot data
	ImageData  []byte    `json:"image_data"`
	CapturedAt time.Time `json:"captured_at"`
	Format     string    `json:"format"` // "png"

	// Analysis results (optional, set by LLM link)
	Analysis *LLMAnalysisResult `json:"analysis,omitempty"`
}

// GetAnalyzableData returns the binary image data for LLM analysis
func (s *ScreenshotData) GetAnalyzableData() []byte {
	return s.ImageData
}

// GetContentType returns that this is image content
func (s *ScreenshotData) GetContentType() ContentType {
	return ContentTypeImage
}

// GetMediaType returns the media type based on the format
func (s *ScreenshotData) GetMediaType() string {
	switch s.Format {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	default:
		return "image/png" // Default fallback
	}
}

// SetAnalysisResult stores the LLM analysis results
func (s *ScreenshotData) SetAnalysisResult(result LLMAnalysisResult) {
	s.Analysis = &result
}

// GetAnalysisResult retrieves the LLM analysis results if available
func (s *ScreenshotData) GetAnalysisResult() *LLMAnalysisResult {
	return s.Analysis
}

// HasAnalysis returns true if LLM analysis has been performed
func (s *ScreenshotData) HasAnalysis() bool {
	return s.Analysis != nil
}

// GetFilename generates a filename for saving the screenshot to disk
func (s *ScreenshotData) GetFilename() string {
	timestamp := s.CapturedAt.Format("20060102-150405")
	return fmt.Sprintf("%s-ec2-screenshot-%s-%s.%s", s.AccountID, s.InstanceID, timestamp, s.Format)
}

// GetDirectory generates a directory path for organizing screenshots
func (s *ScreenshotData) GetDirectory() string {
	return "ec2-console-screenshots"
}

// detectImageFormat determines the image format from the binary data
func detectImageFormat(data []byte) string {
	if len(data) < 4 {
		return "png" // Default fallback
	}

	// Check for PNG signature (89 50 4E 47)
	if len(data) >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return "png"
	}

	// Check for JPEG signature (FF D8 FF)
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "jpeg"
	}

	// Check for GIF signature (47 49 46)
	if len(data) >= 6 && data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
		return "gif"
	}

	// Check for WebP signature (52 49 46 46 ... 57 45 42 50)
	if len(data) >= 12 && data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
		data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50 {
		return "webp"
	}

	return "png" // Default fallback
}

// NewScreenshotData creates a new ScreenshotData instance from an EnrichedResourceDescription
func NewScreenshotData(resource *EnrichedResourceDescription, imageData []byte) *ScreenshotData {
	return &ScreenshotData{
		InstanceID: resource.Identifier,
		Region:     resource.Region,
		AccountID:  resource.AccountId,
		ARN:        resource.Arn,
		ImageData:  imageData,
		CapturedAt: time.Now(),
		Format:     detectImageFormat(imageData),
		Analysis:   nil,
	}
}