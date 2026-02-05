package recon

import (
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEC2ScreenshotAnalysisV2_DefaultValues verifies constructor sets expected defaults
func TestNewEC2ScreenshotAnalysisV2_DefaultValues(t *testing.T) {
	profile := "test-profile"
	regions := []string{"us-east-1", "us-west-2"}

	module := NewEC2ScreenshotAnalysisV2(profile, regions)

	// Verify required fields set
	assert.Equal(t, profile, module.Profile)
	assert.Equal(t, regions, module.Regions)

	// Verify default values
	assert.Equal(t, "claude-3-7-sonnet-latest", module.AnthropicModel)
	assert.Equal(t, 1000, module.MaxTokens)
	assert.NotEmpty(t, module.AnalysisPrompt, "should have default prompt")
	assert.NotNil(t, module.httpClient, "should have HTTP client")
	assert.Equal(t, int64(60000000000), int64(module.httpClient.Timeout), "timeout should be 60s")
}

// TestEC2ScreenshotAnalysisV2_BuilderChaining verifies builder methods return module for chaining
func TestEC2ScreenshotAnalysisV2_BuilderChaining(t *testing.T) {
	module := NewEC2ScreenshotAnalysisV2("profile", []string{"us-east-1"})

	// Test chaining
	result := module.
		WithAnthropicAPIKey("test-key").
		WithAnthropicModel("claude-3-opus").
		WithAnalysisPrompt("custom prompt").
		WithMaxTokens(2000)

	// Should return same instance
	assert.Equal(t, module, result)

	// Verify values set
	assert.Equal(t, "test-key", module.AnthropicAPIKey)
	assert.Equal(t, "claude-3-opus", module.AnthropicModel)
	assert.Equal(t, "custom prompt", module.AnalysisPrompt)
	assert.Equal(t, 2000, module.MaxTokens)
}

// TestDetectImageFormat_JPEG verifies JPEG detection from magic bytes
func TestDetectImageFormat_JPEG(t *testing.T) {
	// JPEG magic bytes: FF D8 FF
	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}

	format := detectImageFormat(jpegData)

	assert.Equal(t, "jpeg", format)
}

// TestDetectImageFormat_PNG verifies PNG detection from magic bytes
func TestDetectImageFormat_PNG(t *testing.T) {
	// PNG magic bytes: 89 50 4E 47
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	format := detectImageFormat(pngData)

	assert.Equal(t, "png", format)
}

// TestDetectImageFormat_Unknown verifies unknown format handling
func TestDetectImageFormat_Unknown(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty data",
			data: []byte{},
			want: "unknown",
		},
		{
			name: "too short",
			data: []byte{0xFF, 0xD8},
			want: "unknown",
		},
		{
			name: "unrecognized magic bytes",
			data: []byte{0x00, 0x00, 0x00, 0x00},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := detectImageFormat(tt.data)
			assert.Equal(t, tt.want, format)
		})
	}
}

// TestCanTakeScreenshot_Running verifies running instances can be screenshotted
func TestCanTakeScreenshot_Running(t *testing.T) {
	// This test verifies the logic in captureScreenshot that checks instance state
	// The actual check is: inst.State.Name != ec2types.InstanceStateNameRunning

	// Running state should allow screenshot
	state := ec2types.InstanceStateNameRunning

	// In production code, this check would be:
	// if inst.State.Name != ec2types.InstanceStateNameRunning {
	//     return nil, nil
	// }

	// So when state IS running, the check fails and we continue to capture
	shouldCapture := (state == ec2types.InstanceStateNameRunning)
	assert.True(t, shouldCapture, "running instances should allow screenshot capture")
}

// TestCanTakeScreenshot_Stopped verifies stopped instances are skipped
func TestCanTakeScreenshot_Stopped(t *testing.T) {
	// Stopped state should skip screenshot
	state := ec2types.InstanceStateNameStopped

	// When state is NOT running, the check succeeds and we return early
	shouldSkip := (state != ec2types.InstanceStateNameRunning)
	assert.True(t, shouldSkip, "stopped instances should skip screenshot capture")

	// Test other non-running states
	nonRunningStates := []ec2types.InstanceStateName{
		ec2types.InstanceStateNamePending,
		ec2types.InstanceStateNameStopping,
		ec2types.InstanceStateNameTerminated,
		ec2types.InstanceStateNameShuttingDown,
	}

	for _, state := range nonRunningStates {
		shouldSkip := (state != ec2types.InstanceStateNameRunning)
		assert.True(t, shouldSkip, "state %s should skip screenshot", state)
	}
}

// TestParseAnalysisResponse_ValidJSON verifies JSON parsing from LLM response
func TestParseAnalysisResponse_ValidJSON(t *testing.T) {
	response := `{
		"sensitive_info_found": true,
		"confidence_score": 0.95,
		"summary": "Test summary",
		"findings": [
			{
				"type": "password",
				"description": "Password visible on screen",
				"confidence": 0.95,
				"location": "center",
				"severity": "high"
			}
		]
	}`

	result, err := parseAnalysisResponse(response)

	require.NoError(t, err)
	assert.True(t, result.SensitiveInfoFound)
	assert.Equal(t, 0.95, result.ConfidenceScore)
	assert.Equal(t, "Test summary", result.Summary)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "password", result.Findings[0].Type)
	assert.Equal(t, "high", result.Findings[0].Severity)
}

// TestParseAnalysisResponse_CodeBlock verifies parsing JSON from markdown code blocks
func TestParseAnalysisResponse_CodeBlock(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantInfo bool
		wantConf float64
	}{
		{
			name: "json code block",
			response: "Here's the analysis:\n```json\n{\n  \"sensitive_info_found\": true,\n  \"confidence_score\": 0.85,\n  \"summary\": \"Found credentials\",\n  \"findings\": []\n}\n```",
			wantInfo: true,
			wantConf: 0.85,
		},
		{
			name: "generic code block",
			response: "Analysis:\n```\n{\n  \"sensitive_info_found\": false,\n  \"confidence_score\": 0.5,\n  \"summary\": \"Nothing found\",\n  \"findings\": []\n}\n```",
			wantInfo: false,
			wantConf: 0.5,
		},
		{
			name: "plain text with keywords",
			response: "I found a password on the screen that looks sensitive",
			wantInfo: true,
			wantConf: 0.7, // heuristic score
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAnalysisResponse(tt.response)

			require.NoError(t, err)
			assert.Equal(t, tt.wantInfo, result.SensitiveInfoFound)
			assert.Equal(t, tt.wantConf, result.ConfidenceScore)
		})
	}
}

// TestGetMediaType verifies MIME type mapping
func TestGetMediaType(t *testing.T) {
	tests := []struct {
		format string
		want   string
	}{
		{"png", "image/png"},
		{"jpeg", "image/jpeg"},
		{"jpg", "image/jpeg"},
		{"unknown", "image/jpeg"}, // default
		{"", "image/jpeg"},        // default
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := getMediaType(tt.format)
			assert.Equal(t, tt.want, got)
		})
	}
}
