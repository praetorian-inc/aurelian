package azure

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

type AzureConditionalAccessAnalysisOutputFormatterLink struct {
	*chain.Base
}

func NewAzureConditionalAccessAnalysisOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessAnalysisOutputFormatterLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
	}
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) Process(input any) error {
	// Expect a single ConditionalAccessAnalysisResult from the LLM analyzer
	analysisResult, ok := input.(ConditionalAccessAnalysisResult)
	if !ok {
		return fmt.Errorf("expected ConditionalAccessAnalysisResult, got %T", input)
	}
	
	l.Logger.Debug("Received policy set analysis result", "policy_set_id", analysisResult.PolicySetID, "policies_analyzed", analysisResult.PoliciesAnalyzed)

	// Generate JSON output
	if err := l.generateJSONOutput(analysisResult); err != nil {
		return fmt.Errorf("failed to generate JSON output: %w", err)
	}

	// Generate console output (directly to stdout, not sent through pipeline)
	l.generateConsoleOutput(analysisResult)

	return nil
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) generateJSONOutput(result ConditionalAccessAnalysisResult) error {
	outputDir, _ := cfg.As[string](l.Arg("output"))

	// Create filename with high precision timestamp
	timestamp := time.Now().Format("20060102-150405.000")
	filename := fmt.Sprintf("conditional-access-analysis-%s.json", timestamp)
	jsonFilePath := filepath.Join(outputDir, filename)

	// Create structured output data with metadata
	metadata := map[string]interface{}{
		"collectedAt":     time.Now().UTC().Format(time.RFC3339),
		"policiesAnalyzed": result.PoliciesAnalyzed,
		"module":          "conditional-access-analysis",
	}

	outputData := map[string]interface{}{
		"metadata": metadata,
		"result":   result,
	}

	// Send JSON output
	jsonOutput := outputters.NewNamedOutputData(outputData, jsonFilePath)
	return l.Send(jsonOutput)
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) generateConsoleOutput(result ConditionalAccessAnalysisResult) {
	// Print console summary
	fmt.Printf("\nConditional Access Policy Set Analysis Results\n")
	fmt.Printf("============================================\n\n")
	
	// Analysis metadata
	fmt.Printf("Policy Set Analysis Summary:\n")
	fmt.Printf("- Policy Set ID: %s\n", result.PolicySetID)
	fmt.Printf("- Policies Analyzed: %d\n", result.PoliciesAnalyzed)
	fmt.Printf("- Overall Risk Level: %s\n", l.formatRiskLevel(result.OverallRiskLevel))
	fmt.Printf("- Security Observations Found: %d\n", len(result.ObservationsDetected))
	fmt.Printf("- LLM Provider: %s\n", result.LLMProvider)
	fmt.Printf("- Analysis Timestamp: %s\n\n", result.AnalysisTimestamp)

	// Show detailed security observations
	if len(result.ObservationsDetected) > 0 {
		fmt.Printf("Security Observations Detected:\n")
		for i, observation := range result.ObservationsDetected {
			fmt.Printf("\n%d. %s [%s] (Confidence: %s)\n\n", i+1, observation.Title, observation.Type, observation.Confidence)
			fmt.Printf("Description:\n%s\n\n", l.convertNumbersToBullets(observation.Description))
			if observation.TechnicalDetails != "" {
				fmt.Printf("Technical Details:\n%s\n\n", l.convertNumbersToBullets(observation.TechnicalDetails))
			}
			if observation.PotentialImpact != "" {
				fmt.Printf("Potential Impact:\n%s\n\n", l.convertNumbersToBullets(observation.PotentialImpact))
			}
			if observation.ExploitScenario != "" {
				fmt.Printf("Exploit Scenario:\n%s\n\n", l.convertNumbersToBullets(observation.ExploitScenario))
			}
			
			// Add separator line between observations (except for the last one)
			if i < len(result.ObservationsDetected)-1 {
				fmt.Printf("============================================\n")
			}
		}
		fmt.Printf("\n")
	}
	
	// Show recommendations
	if len(result.Recommendations) > 0 {
		fmt.Printf("Recommendations for Policy Set:\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
		fmt.Printf("\n")
	}
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) formatRiskLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return level
	}
}

// Helper function to get critical gaps from the policy set analysis
func (l *AzureConditionalAccessAnalysisOutputFormatterLink) getCriticalObservations(observations []ObservationXML) []ObservationXML {
	var critical []ObservationXML
	for _, observation := range observations {
		if strings.ToLower(observation.Type) == "critical" || strings.ToLower(observation.Type) == "high" {
			critical = append(critical, observation)
		}
	}
	return critical
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// convertNumbersToBullets converts numbered lists (1. 2. 3.) to bullet points (* * *)
func (l *AzureConditionalAccessAnalysisOutputFormatterLink) convertNumbersToBullets(text string) string {
	// Handle text that might have numbered lists on the same line separated by spaces
	// First, check if we have numbered items that aren't on separate lines
	if strings.Contains(text, ". ") && !strings.Contains(text, "\n") {
		// Split on numbered patterns and reconstruct with line breaks
		parts := []string{}
		remainingText := text
		
		for {
			// Find the next number pattern (digit(s) followed by ". ")
			found := false
			for i := 1; i <= len(remainingText)-3; i++ {
				if i < len(remainingText) && remainingText[i] == '.' && i+1 < len(remainingText) && remainingText[i+1] == ' ' {
					// Check if character before the dot is a digit
					if remainingText[i-1] >= '0' && remainingText[i-1] <= '9' {
						// Check if this is the start of a numbered item (not part of a larger number)
						if i > 1 && remainingText[i-2] >= '0' && remainingText[i-2] <= '9' {
							// Multi-digit number, continue searching
							continue
						}
						
						// Found a numbered item
						if len(parts) == 0 {
							// First item - everything before this point
							parts = append(parts, strings.TrimSpace(remainingText[:i-1]))
						}
						
						// Find the end of this item (next number or end of string)
						nextItemStart := -1
						for j := i + 3; j <= len(remainingText)-3; j++ {
							if j < len(remainingText) && remainingText[j] == '.' && j+1 < len(remainingText) && remainingText[j+1] == ' ' {
								if remainingText[j-1] >= '0' && remainingText[j-1] <= '9' {
									nextItemStart = j - 1
									break
								}
							}
						}
						
						var itemText string
						if nextItemStart == -1 {
							// Last item
							itemText = strings.TrimSpace(remainingText[i+2:])
							parts = append(parts, "* "+itemText)
							remainingText = ""
						} else {
							// More items follow
							itemText = strings.TrimSpace(remainingText[i+2:nextItemStart])
							parts = append(parts, "* "+itemText)
							remainingText = remainingText[nextItemStart:]
							found = true
						}
						break
					}
				}
			}
			if !found || remainingText == "" {
				break
			}
		}
		
		if len(parts) > 1 {
			return strings.Join(parts[1:], "\n") // Skip first empty part
		}
	}
	
	// Handle text that already has line breaks - process line by line
	lines := strings.Split(text, "\n")
	
	for i, line := range lines {
		// Check if line contains numbered list pattern
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		
		// Look for pattern: digit(s) + ". " at start of trimmed line
		dotSpaceIdx := strings.Index(trimmed, ". ")
		if dotSpaceIdx > 0 && dotSpaceIdx <= 3 { // Allow 1-3 digit numbers (1-999)
			// Extract the number part
			numberPart := trimmed[:dotSpaceIdx]
			
			// Verify it's all digits
			allDigits := true
			for _, char := range numberPart {
				if char < '0' || char > '9' {
					allDigits = false
					break
				}
			}
			
			if allDigits {
				// Calculate leading whitespace to preserve indentation
				leadingSpaces := len(line) - len(trimmed)
				indent := strings.Repeat(" ", leadingSpaces)
				
				// Replace the numbered item with bullet
				restOfLine := trimmed[dotSpaceIdx+2:] // Skip ". "
				lines[i] = indent + "* " + restOfLine
			}
		}
	}
	
	return strings.Join(lines, "\n")
}