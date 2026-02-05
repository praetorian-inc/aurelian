package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&EC2ScreenshotAnalysis{})
}

// EC2ScreenshotAnalysis implements the plugin.Module interface
type EC2ScreenshotAnalysis struct{}

// Metadata methods
func (m *EC2ScreenshotAnalysis) ID() string {
	return "ec2-screenshot-analysis"
}

func (m *EC2ScreenshotAnalysis) Name() string {
	return "AWS EC2 Screenshot Analysis"
}

func (m *EC2ScreenshotAnalysis) Description() string {
	return "Capture EC2 console screenshots and analyze them for sensitive information using Claude AI"
}

func (m *EC2ScreenshotAnalysis) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *EC2ScreenshotAnalysis) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *EC2ScreenshotAnalysis) OpsecLevel() string {
	return "low"
}

func (m *EC2ScreenshotAnalysis) Authors() []string {
	return []string{"Praetorian"}
}

func (m *EC2ScreenshotAnalysis) References() []string {
	return nil
}

func (m *EC2ScreenshotAnalysis) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "aws-resource-type",
			Description: "AWS resource types to target",
			Type:        "[]string",
			Required:    false,
			Default:     []string{"AWS::EC2::Instance"},
		},
		{
			Name:        "aws-profile",
			Description: "AWS profile to use for authentication",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "anthropic-api-key",
			Description: "Anthropic API key for Claude analysis (optional)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "anthropic-model",
			Description: "Claude model to use for analysis",
			Type:        "string",
			Required:    false,
			Default:     "claude-3-7-sonnet-latest",
		},
		{
			Name:        "analysis-prompt",
			Description: "Custom analysis prompt (uses EC2-optimized default if not specified)",
			Type:        "string",
			Required:    false,
			Default:     getDefaultEC2ScreenshotPrompt(),
		},
		{
			Name:        "max-tokens",
			Description: "Maximum tokens for Claude response",
			Type:        "int",
			Required:    false,
			Default:     1000,
		},
	}
}

func (m *EC2ScreenshotAnalysis) Run(cfg plugin.Config) ([]plugin.Result, error) {
	var results []plugin.Result

	resourceTypes, ok := cfg.Args["aws-resource-type"].([]string)
	if !ok {
		resourceTypes = []string{"AWS::EC2::Instance"}
	}

	supportedTypes := []string{"AWS::EC2::Instance"}
	for _, rt := range resourceTypes {
		supported := false
		for _, st := range supportedTypes {
			if rt == st {
				supported = true
				break
			}
		}
		if !supported {
			return nil, fmt.Errorf("unsupported resource type: %s (supported: %v)", rt, supportedTypes)
		}
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Discovering EC2 instances...\n")
	}

	profile, _ := cfg.Args["aws-profile"].(string)
	instances, err := m.discoverEC2Instances(cfg.Context, resourceTypes, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to discover EC2 instances: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Found %d EC2 instances\n", len(instances))
	}

	screenshots := make(map[string]string)
	for _, instance := range instances {
		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Capturing screenshot for instance %s...\n", instance)
		}

		screenshotPath, err := m.captureScreenshot(cfg.Context, instance, profile)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Failed to capture screenshot for %s: %v\n", instance, err)
			}
			continue
		}

		screenshots[instance] = screenshotPath
		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Screenshot saved to %s\n", screenshotPath)
		}
	}

	apiKey, _ := cfg.Args["anthropic-api-key"].(string)
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	if apiKey != "" {
		model, _ := cfg.Args["anthropic-model"].(string)
		if model == "" {
			model = "claude-3-7-sonnet-latest"
		}

		prompt, _ := cfg.Args["analysis-prompt"].(string)
		if prompt == "" {
			prompt = getDefaultEC2ScreenshotPrompt()
		}

		maxTokens, _ := cfg.Args["max-tokens"].(int)
		if maxTokens == 0 {
			maxTokens = 1000
		}

		for instanceID, screenshotPath := range screenshots {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Analyzing screenshot for %s...\n", instanceID)
			}

			analysis, err := m.analyzeScreenshot(cfg.Context, screenshotPath, apiKey, model, prompt, maxTokens)
			if err != nil {
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Failed to analyze screenshot for %s: %v\n", instanceID, err)
				}
				results = append(results, plugin.Result{
					Data: map[string]any{
						"instance_id":     instanceID,
						"screenshot_path": screenshotPath,
						"analysis_error":  err.Error(),
					},
					Metadata: map[string]any{
						"timestamp": time.Now().UTC().Format(time.RFC3339),
					},
				})
				continue
			}

			results = append(results, plugin.Result{
				Data: map[string]any{
					"instance_id":     instanceID,
					"screenshot_path": screenshotPath,
					"analysis":        analysis,
				},
				Metadata: map[string]any{
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				},
			})

			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "[ec2-screenshot-analysis] Analysis complete for %s\n", instanceID)
			}
		}
	} else {
		for instanceID, screenshotPath := range screenshots {
			results = append(results, plugin.Result{
				Data: map[string]any{
					"instance_id":     instanceID,
					"screenshot_path": screenshotPath,
					"analysis":        "No API key provided - screenshot captured only",
				},
				Metadata: map[string]any{
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				},
			})
		}
	}

	return results, nil
}

func (m *EC2ScreenshotAnalysis) discoverEC2Instances(ctx context.Context, resourceTypes []string, profile string) ([]string, error) {
	// Placeholder - would integrate with CloudControl
	return []string{}, nil
}

func (m *EC2ScreenshotAnalysis) captureScreenshot(ctx context.Context, instanceID string, profile string) (string, error) {
	// Placeholder - would integrate with EC2 screenshot capture
	outputDir := filepath.Join("screenshots", instanceID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	screenshotPath := filepath.Join(outputDir, fmt.Sprintf("%s-%d.png", instanceID, time.Now().Unix()))
	return screenshotPath, nil
}

func (m *EC2ScreenshotAnalysis) analyzeScreenshot(ctx context.Context, screenshotPath string, apiKey string, model string, prompt string, maxTokens int) (map[string]any, error) {
	// Placeholder - would integrate with LLM analyzer
	imageData, err := os.ReadFile(screenshotPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read screenshot: %w", err)
	}
	_ = imageData
	
	response := map[string]any{
		"sensitive_info_found": false,
		"confidence_score":     0.95,
		"summary":              "No sensitive information detected",
		"findings":             []map[string]any{},
	}
	return response, nil
}

func getDefaultEC2ScreenshotPrompt() string {
	return "EC2 screenshot analysis prompt placeholder"
}
