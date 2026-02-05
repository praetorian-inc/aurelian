package recon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

// EC2ScreenshotAnalysisV2 captures EC2 console screenshots and analyzes them with Claude AI.
// Replaces the Janus chain-based AWSScreenshotAnalysis module.
type EC2ScreenshotAnalysisV2 struct {
	// Required
	Profile string
	Regions []string

	// Optional - LLM Analysis
	AnthropicAPIKey string
	AnthropicModel  string
	AnalysisPrompt  string
	MaxTokens       int

	// Internal
	httpClient *http.Client
	config     aws.Config
	ec2Clients map[string]*ec2.Client
	ccClients  map[string]*cloudcontrol.Client
}

// ScreenshotAnalysisResult represents a single EC2 screenshot analysis result.
type ScreenshotAnalysisResult struct {
	InstanceID       string
	Region           string
	AccountID        string
	Screenshot       []byte
	ScreenshotFormat string
	Analysis         *types.LLMAnalysisResult
	CapturedAt       time.Time
	Error            string
}

// EC2ScreenshotAnalysisResults contains all screenshot analysis results.
type EC2ScreenshotAnalysisResults struct {
	Results      []*ScreenshotAnalysisResult
	TotalCount   int
	SuccessCount int
	FailedCount  int
}

// NewEC2ScreenshotAnalysisV2 creates a new v2 EC2 screenshot analyzer.
func NewEC2ScreenshotAnalysisV2(profile string, regions []string) *EC2ScreenshotAnalysisV2 {
	return &EC2ScreenshotAnalysisV2{
		Profile:        profile,
		Regions:        regions,
		AnthropicModel: "claude-3-7-sonnet-latest",
		MaxTokens:      1000,
		AnalysisPrompt: getDefaultEC2ScreenshotPrompt(),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// WithAnthropicAPIKey sets the Anthropic API key for analysis.
func (e *EC2ScreenshotAnalysisV2) WithAnthropicAPIKey(key string) *EC2ScreenshotAnalysisV2 {
	e.AnthropicAPIKey = key
	return e
}

// WithAnthropicModel overrides the default Anthropic model.
func (e *EC2ScreenshotAnalysisV2) WithAnthropicModel(model string) *EC2ScreenshotAnalysisV2 {
	e.AnthropicModel = model
	return e
}

// WithAnalysisPrompt overrides the default analysis prompt.
func (e *EC2ScreenshotAnalysisV2) WithAnalysisPrompt(prompt string) *EC2ScreenshotAnalysisV2 {
	e.AnalysisPrompt = prompt
	return e
}

// WithMaxTokens sets the maximum tokens for LLM response.
func (e *EC2ScreenshotAnalysisV2) WithMaxTokens(tokens int) *EC2ScreenshotAnalysisV2 {
	e.MaxTokens = tokens
	return e
}

// Run executes the EC2 screenshot analysis workflow.
func (e *EC2ScreenshotAnalysisV2) Run(ctx context.Context) (*EC2ScreenshotAnalysisResults, error) {
	// 1. Initialize AWS clients
	if err := e.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	// 2. Discover EC2 instances across all regions
	instances, err := e.discoverInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("instance discovery failed: %w", err)
	}

	slog.Info("Discovered EC2 instances", "count", len(instances))

	// 3. Capture screenshots with bounded concurrency
	results := &EC2ScreenshotAnalysisResults{}
	screenshotResults := make([]*ScreenshotAnalysisResult, 0, len(instances))

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Maximum 10 concurrent screenshot captures

	resultCh := make(chan *ScreenshotAnalysisResult, len(instances))

	for _, instance := range instances {
		instance := instance
		g.Go(func() error {
			result, err := e.captureScreenshot(gCtx, &instance)
			if err != nil {
				slog.Warn("Failed to capture screenshot",
					"instance_id", instance.Identifier,
					"error", err)
				// Don't fail the entire workflow for one screenshot failure
				return nil
			}
			if result != nil {
				resultCh <- result
			}
			return nil
		})
	}

	// Wait for all screenshot captures to complete
	if err := g.Wait(); err != nil {
		close(resultCh)
		return nil, fmt.Errorf("screenshot capture failed: %w", err)
	}
	close(resultCh)

	// Collect results
	for result := range resultCh {
		screenshotResults = append(screenshotResults, result)
	}

	// 4. Optionally analyze screenshots with Claude AI
	if e.AnthropicAPIKey != "" && len(screenshotResults) > 0 {
		slog.Info("Starting LLM analysis", "screenshot_count", len(screenshotResults))

		g2, gCtx2 := errgroup.WithContext(ctx)
		g2.SetLimit(5) // Maximum 5 concurrent LLM analyses (API rate limits)

		for _, result := range screenshotResults {
			result := result
			g2.Go(func() error {
				if err := e.analyzeScreenshot(gCtx2, result); err != nil {
					slog.Warn("Failed to analyze screenshot",
						"instance_id", result.InstanceID,
						"error", err)
					// Don't fail for analysis errors
				}
				return nil
			})
		}

		if err := g2.Wait(); err != nil {
			return nil, fmt.Errorf("screenshot analysis failed: %w", err)
		}
	}

	// 5. Aggregate results
	results.Results = screenshotResults
	results.TotalCount = len(instances)
	results.SuccessCount = len(screenshotResults)
	results.FailedCount = results.TotalCount - results.SuccessCount

	return results, nil
}

// initialize sets up AWS clients for all regions.
func (e *EC2ScreenshotAnalysisV2) initialize(ctx context.Context) error {
	// Load base AWS config
	cfg, err := helpers.GetAWSCfg("us-east-1", e.Profile, nil, "", nil)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	e.config = cfg

	// Create EC2 and CloudControl clients for each region
	e.ec2Clients = make(map[string]*ec2.Client)
	e.ccClients = make(map[string]*cloudcontrol.Client)

	for _, region := range e.Regions {
		regionCfg, err := helpers.GetAWSCfg(region, e.Profile, nil, "", nil)
		if err != nil {
			return fmt.Errorf("failed to load config for region %s: %w", region, err)
		}
		e.ec2Clients[region] = ec2.NewFromConfig(regionCfg)
		e.ccClients[region] = cloudcontrol.NewFromConfig(regionCfg)
	}

	return nil
}

// discoverInstances finds all EC2 instances across configured regions using CloudControl.
func (e *EC2ScreenshotAnalysisV2) discoverInstances(ctx context.Context) ([]types.EnrichedResourceDescription, error) {
	var instances []types.EnrichedResourceDescription

	// Get account ID
	accountId, err := helpers.GetAccountId(e.config)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	for _, region := range e.Regions {
		client := e.ccClients[region]

		// List EC2 instances using CloudControl
		input := &cloudcontrol.ListResourcesInput{
			TypeName: aws.String("AWS::EC2::Instance"),
		}

		paginator := cloudcontrol.NewListResourcesPaginator(client, input)

		for paginator.HasMorePages() {
			output, err := paginator.NextPage(ctx)
			if err != nil {
				slog.Warn("Failed to list instances in region",
					"region", region,
					"error", err)
				// Continue with other regions
				break
			}

			for _, desc := range output.ResourceDescriptions {
				if desc.Identifier == nil {
					continue
				}

				// Parse properties to check instance state
				var props map[string]interface{}
				if desc.Properties != nil {
					if err := json.Unmarshal([]byte(*desc.Properties), &props); err != nil {
						slog.Warn("Failed to parse instance properties",
							"instance_id", *desc.Identifier,
							"error", err)
						continue
					}
				}

				// Only capture screenshots for running instances
				if state, ok := props["State"].(map[string]interface{}); ok {
					if name, ok := state["Name"].(string); ok && name != "running" {
						slog.Debug("Skipping non-running instance",
							"instance_id", *desc.Identifier,
							"state", name)
						continue
					}
				}

				erd := types.EnrichedResourceDescription{
					Identifier: *desc.Identifier,
					TypeName:   "AWS::EC2::Instance",
					Region:     region,
					AccountId:  accountId,
				}

				if desc.Properties != nil {
					erd.Properties = *desc.Properties
				}

				instances = append(instances, erd)
			}
		}
	}

	return instances, nil
}

// captureScreenshot captures a console screenshot for a single EC2 instance.
func (e *EC2ScreenshotAnalysisV2) captureScreenshot(ctx context.Context, instance *types.EnrichedResourceDescription) (*ScreenshotAnalysisResult, error) {
	client := e.ec2Clients[instance.Region]

	// First verify instance state
	descInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instance.Identifier},
	}

	descOutput, err := client.DescribeInstances(ctx, descInput)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance: %w", err)
	}

	if len(descOutput.Reservations) == 0 || len(descOutput.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance not found: %s", instance.Identifier)
	}

	inst := descOutput.Reservations[0].Instances[0]

	// Only capture screenshots for running instances
	if inst.State.Name != ec2types.InstanceStateNameRunning {
		slog.Debug("Skipping screenshot for non-running instance",
			"instance_id", instance.Identifier,
			"state", inst.State.Name)
		return nil, nil
	}

	// Capture the screenshot
	screenshotInput := &ec2.GetConsoleScreenshotInput{
		InstanceId: &instance.Identifier,
		WakeUp:     aws.Bool(false), // Don't wake hibernated instances
	}

	slog.Info("Capturing console screenshot",
		"instance_id", instance.Identifier,
		"region", instance.Region)

	screenshotOutput, err := client.GetConsoleScreenshot(ctx, screenshotInput)
	if err != nil {
		// Handle common errors gracefully
		errMsg := err.Error()
		if strings.Contains(errMsg, "InvalidInstanceID") ||
			strings.Contains(errMsg, "UnsupportedOperation") ||
			strings.Contains(errMsg, "IncorrectInstanceState") {
			slog.Warn("Screenshot not available for instance",
				"instance_id", instance.Identifier,
				"error", errMsg)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to capture screenshot: %w", err)
	}

	if screenshotOutput.ImageData == nil || *screenshotOutput.ImageData == "" {
		slog.Warn("No image data returned", "instance_id", instance.Identifier)
		return nil, nil
	}

	// Decode the base64 image data
	imageBytes, err := base64.StdEncoding.DecodeString(*screenshotOutput.ImageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 image: %w", err)
	}

	// Determine image format from magic bytes
	format := detectImageFormat(imageBytes)

	result := &ScreenshotAnalysisResult{
		InstanceID:       instance.Identifier,
		Region:           instance.Region,
		AccountID:        instance.AccountId,
		Screenshot:       imageBytes,
		ScreenshotFormat: format,
		CapturedAt:       time.Now(),
	}

	slog.Info("Successfully captured screenshot",
		"instance_id", instance.Identifier,
		"size_bytes", len(imageBytes),
		"format", format)

	return result, nil
}

// analyzeScreenshot analyzes a screenshot with Claude AI.
func (e *EC2ScreenshotAnalysisV2) analyzeScreenshot(ctx context.Context, result *ScreenshotAnalysisResult) error {
	if e.AnthropicAPIKey == "" {
		return fmt.Errorf("no Anthropic API key configured")
	}

	slog.Info("Starting LLM analysis",
		"instance_id", result.InstanceID,
		"model", e.AnthropicModel)

	startTime := time.Now()

	// Build API request
	encodedImage := base64.StdEncoding.EncodeToString(result.Screenshot)

	request := map[string]interface{}{
		"model":      e.AnthropicModel,
		"max_tokens": e.MaxTokens,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "image",
						"source": map[string]interface{}{
							"type":       "base64",
							"media_type": getMediaType(result.ScreenshotFormat),
							"data":       encodedImage,
						},
					},
					{
						"type": "text",
						"text": e.AnalysisPrompt,
					},
				},
			},
		},
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", strings.NewReader(string(requestBody)))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", e.AnthropicAPIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// Send the request
	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for API errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	// Parse the response
	var apiResponse struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResponse.Content) == 0 {
		return fmt.Errorf("no content in API response")
	}

	// Parse the analysis result
	analysisText := apiResponse.Content[0].Text
	analysisResult, err := parseAnalysisResponse(analysisText)
	if err != nil {
		return fmt.Errorf("failed to parse analysis response: %w", err)
	}

	// Add metadata
	analysisResult.AnalysisTimestamp = time.Now()
	analysisResult.Model = e.AnthropicModel
	analysisResult.PromptUsed = e.AnalysisPrompt
	analysisResult.TokensUsed = apiResponse.Usage.InputTokens + apiResponse.Usage.OutputTokens
	analysisResult.AnalysisDuration = time.Since(startTime).Milliseconds()

	result.Analysis = analysisResult

	slog.Info("LLM analysis completed",
		"instance_id", result.InstanceID,
		"sensitive_info_found", analysisResult.SensitiveInfoFound,
		"findings_count", len(analysisResult.Findings),
		"confidence_score", analysisResult.ConfidenceScore,
		"duration_ms", analysisResult.AnalysisDuration)

	return nil
}

// detectImageFormat determines image format from magic bytes.
func detectImageFormat(data []byte) string {
	if len(data) < 4 {
		return "unknown"
	}

	// PNG: 89 50 4E 47
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return "png"
	}

	// JPEG: FF D8 FF
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "jpeg"
	}

	return "unknown"
}

// getMediaType returns the MIME type for a given image format.
func getMediaType(format string) string {
	switch format {
	case "png":
		return "image/png"
	case "jpeg", "jpg":
		return "image/jpeg"
	default:
		return "image/jpeg" // Default to JPEG
	}
}

// parseAnalysisResponse parses the LLM analysis response.
func parseAnalysisResponse(response string) (*types.LLMAnalysisResult, error) {
	// Extract JSON from markdown code blocks if present
	jsonStr := response
	if strings.Contains(response, "```json") {
		start := strings.Index(response, "```json")
		if start != -1 {
			start += 7
			end := strings.Index(response[start:], "```")
			if end != -1 {
				jsonStr = strings.TrimSpace(response[start : start+end])
			}
		}
	} else if strings.Contains(response, "```") {
		start := strings.Index(response, "```")
		if start != -1 {
			start += 3
			end := strings.Index(response[start:], "```")
			if end != -1 {
				jsonStr = strings.TrimSpace(response[start : start+end])
			}
		}
	}

	// Try to parse as JSON
	var result types.LLMAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
		return &result, nil
	}

	// Fall back to text summary
	result = types.LLMAnalysisResult{
		SensitiveInfoFound: false,
		ConfidenceScore:    0.0,
		Summary:            response,
		Findings:           []types.SensitiveFinding{},
	}

	// Simple heuristic: check for sensitive keywords
	lowerResponse := strings.ToLower(response)
	sensitiveKeywords := []string{
		"password", "credential", "api key", "secret", "token",
		"sensitive", "confidential", "private key", "ssh key",
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerResponse, keyword) {
			result.SensitiveInfoFound = true
			result.ConfidenceScore = 0.7
			result.Findings = append(result.Findings, types.SensitiveFinding{
				Type:        "potential_" + strings.ReplaceAll(keyword, " ", "_"),
				Description: fmt.Sprintf("Potential %s detected in content", keyword),
				Confidence:  0.7,
				Location:    "detected_in_analysis",
				Severity:    "medium",
			})
		}
	}

	return &result, nil
}
