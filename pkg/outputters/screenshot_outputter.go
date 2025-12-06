package outputters

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ScreenshotOutputter handles screenshot data by writing files to disk and displaying analysis results
type ScreenshotOutputter struct {
	*BaseFileOutputter
	screenshots     []types.ScreenshotData
	outputDirectory string
}

// NewScreenshotOutputter creates a new screenshot outputter
func NewScreenshotOutputter(configs ...cfg.Config) chain.Outputter {
	o := &ScreenshotOutputter{
		screenshots: make([]types.ScreenshotData, 0),
	}
	o.BaseFileOutputter = NewBaseFileOutputter(o, configs...)
	return o
}

// Initialize sets up the outputter and determines the output directory
func (o *ScreenshotOutputter) Initialize() error {
	// Get base output directory
	outputDir, err := cfg.As[string](o.Arg("output"))
	if err != nil {
		outputDir = "nebula-output" // Fallback default
	}

	// Screenshots will be stored directly in the base output directory
	o.outputDirectory = outputDir

	// Ensure the output directory exists
	if err := o.EnsureOutputPath(filepath.Join(o.outputDirectory, "dummy")); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return nil
}

// Output collects ScreenshotData items for batch processing
func (o *ScreenshotOutputter) Output(v any) error {
	// Check if we received a ScreenshotData type
	if screenshot, ok := v.(*types.ScreenshotData); ok {
		o.screenshots = append(o.screenshots, *screenshot)
		return nil
	}

	// Try direct type assertion
	if screenshot, ok := v.(types.ScreenshotData); ok {
		o.screenshots = append(o.screenshots, screenshot)
		return nil
	}

	// Not a screenshot, silently ignore
	return nil
}

// Complete processes all collected screenshots - writes files and displays analysis
func (o *ScreenshotOutputter) Complete() error {
	if len(o.screenshots) == 0 {
		return nil
	}

	message.Section("EC2 Console Screenshots")

	var totalFiles int
	var totalWithAnalysis int
	var criticalFindings int

	// Process each screenshot
	for _, screenshot := range o.screenshots {
		// Write the screenshot file
		filePath, err := o.writeScreenshotFile(screenshot)
		if err != nil {
			message.Error("Failed to write screenshot file for %s: %v", screenshot.InstanceID, err)
			continue
		}

		totalFiles++

		// Display screenshot info and analysis
		o.displayScreenshotInfo(screenshot, filePath)

		// Count analysis results
		if screenshot.HasAnalysis() {
			totalWithAnalysis++
			critical := screenshot.Analysis.GetCriticalFindings()
			criticalFindings += len(critical)
		}
	}

	// Display summary
	message.Info("Screenshots captured: %d", totalFiles)
	if totalWithAnalysis > 0 {
		message.Info("Screenshots analyzed: %d", totalWithAnalysis)
		if criticalFindings > 0 {
			message.Warning("Critical security findings: %d", criticalFindings)
		}
	}
	message.Info("Screenshots saved to: %s", filepath.Join(o.outputDirectory, "ec2-console-screenshots"))

	return nil
}

// writeScreenshotFile writes a screenshot to disk using the tabularium File model
func (o *ScreenshotOutputter) writeScreenshotFile(screenshot types.ScreenshotData) (string, error) {
	// Create the ec2-console-screenshots subdirectory
	screenshotDir := filepath.Join(o.outputDirectory, screenshot.GetDirectory())
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create screenshot directory: %w", err)
	}

	// Generate filename
	filename := screenshot.GetFilename()
	filePath := filepath.Join(screenshotDir, filename)

	// Use tabularium File model for consistent binary data handling
	file := model.NewFile(filePath)
	file.Bytes = model.SmartBytes(screenshot.ImageData) // Automatic base64 encoding if needed

	// Write the raw binary data directly to disk
	// (The tabularium File model is more for data modeling; for actual file I/O we write directly)
	if err := os.WriteFile(filePath, screenshot.ImageData, 0644); err != nil {
		return "", fmt.Errorf("failed to write screenshot file: %w", err)
	}

	return filePath, nil
}

// displayScreenshotInfo shows information about a screenshot and its analysis
func (o *ScreenshotOutputter) displayScreenshotInfo(screenshot types.ScreenshotData, filePath string) {
	message.Success("Screenshot captured: %s", message.Emphasize(screenshot.InstanceID))
	message.Info("  Region: %s", screenshot.Region)
	message.Info("  Account: %s", screenshot.AccountID)
	message.Info("  File: %s", filePath)
	message.Info("  Size: %s", formatBytes(len(screenshot.ImageData)))
	message.Info("  Captured: %s", screenshot.CapturedAt.Format("2006-01-02 15:04:05"))

	// Display analysis results if available
	if screenshot.HasAnalysis() {
		o.displayAnalysisResults(screenshot.Analysis)
	} else {
		message.Info("  Analysis: Not performed (API key not provided)")
	}

	fmt.Println() // Add spacing between screenshots
}

// displayAnalysisResults shows the LLM analysis results
func (o *ScreenshotOutputter) displayAnalysisResults(analysis *types.LLMAnalysisResult) {
	// Determine highest severity from findings
	highestSeverity := "info"
	if len(analysis.Findings) > 0 {
		for _, finding := range analysis.Findings {
			switch finding.Severity {
			case "critical":
				highestSeverity = "critical"
			case "high":
				if highestSeverity != "critical" {
					highestSeverity = "high"
				}
			case "medium":
				if highestSeverity != "critical" && highestSeverity != "high" {
					highestSeverity = "medium"
				}
			case "low":
				if highestSeverity == "info" {
					highestSeverity = "low"
				}
			}
		}
	}

	// Format output: [severity] summary
	if analysis.SensitiveInfoFound {
		message.Warning("  Analysis: [%s] %s", highestSeverity, analysis.Summary)
	} else {
		message.Success("  Analysis: [%s] %s", highestSeverity, analysis.Summary)
	}
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Params defines the parameters accepted by this outputter
func (o *ScreenshotOutputter) Params() []cfg.Param {
	return []cfg.Param{
		// Use the standard output directory parameter from options
		options.OutputDir(),
	}
}