package azure

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
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
	// Handle both analysis results (when LLM enabled) and passthrough policies (when LLM disabled)
	switch v := input.(type) {
	case ConditionalAccessAnalysisResult:
		// LLM analysis was performed - handle analysis results
		l.Logger.Debug("Received policy set analysis result", "policy_set_id", v.PolicySetID, "policies_analyzed", v.PoliciesAnalyzed)

		// Wrap analysis result with metadata structure for tenant ID filename
		wrappedAnalysis := l.createAnalysisOutputData(v)
		
		if err := l.Send(wrappedAnalysis); err != nil {
			return fmt.Errorf("failed to send analysis JSON output: %w", err)
		}

		// Generate console output (directly to stdout, not sent through pipeline)
		l.generateConsoleOutput(v)

	case []EnrichedConditionalAccessPolicy:
		// LLM analysis was disabled - handle recon data passthrough by creating recon JSON
		l.Logger.Debug("LLM analysis disabled, creating recon JSON output", "policy_count", len(v))

		// Create recon JSON file with structured metadata
		reconFilePath := l.generateReconJSONFilename()
		outputData := l.createStructuredOutputData(v)
		reconOutputData := outputters.NewNamedOutputData(outputData, reconFilePath)
		
		if err := l.Send(reconOutputData); err != nil {
			return fmt.Errorf("failed to send recon JSON output: %w", err)
		}

	case nil:
		// Handle case where analysis failed and returned nil
		l.Logger.Debug("Received nil input - analysis likely failed")
		
		// Create minimal analysis output data with metadata for tenant ID filename
		emptyAnalysisData := l.createEmptyAnalysisOutputData()
		
		if err := l.Send(emptyAnalysisData); err != nil {
			return fmt.Errorf("failed to send failed analysis JSON output: %w", err)
		}

	default:
		return fmt.Errorf("expected ConditionalAccessAnalysisResult or []EnrichedConditionalAccessPolicy, got %T", input)
	}

	return nil
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


func (l *AzureConditionalAccessAnalysisOutputFormatterLink) generateReconJSONFilename() string {
	outputDir, _ := cfg.As[string](l.Arg("output"))

	// Create filename with timestamp (used when LLM analysis is disabled)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("conditional-access-policies-%s.json", timestamp)
	return filepath.Join(outputDir, filename)
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) createStructuredOutputData(policies []EnrichedConditionalAccessPolicy) map[string]any {
	// Get tenant ID for metadata
	tenantID, _ := l.getTenantID()

	// Create structured output with metadata wrapper
	structuredData := map[string]any{
		"metadata": map[string]any{
			"tenant_id":       tenantID,
			"policy_count":    len(policies),
			"collection_time": time.Now().Format(time.RFC3339),
			"data_type":       "azure_conditional_access_policies",
		},
		"policies": policies,
	}

	return structuredData
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) createAnalysisOutputData(result ConditionalAccessAnalysisResult) map[string]any {
	// Get tenant ID for metadata
	tenantID, _ := l.getTenantID()

	// Create structured output with metadata wrapper for RuntimeJSONOutputter
	analysisData := map[string]any{
		"metadata": map[string]any{
			"tenantId":        tenantID,
			"data_type":       "azure_conditional_access_analysis",
			"analysis_time":   result.AnalysisTimestamp,
			"policy_set_id":   result.PolicySetID,
			"policies_count":  result.PoliciesAnalyzed,
			"llm_provider":    result.LLMProvider,
		},
		"analysis": result,
	}

	return analysisData
}

func (l *AzureConditionalAccessAnalysisOutputFormatterLink) createEmptyAnalysisOutputData() map[string]any {
	// Get tenant ID for metadata
	tenantID, _ := l.getTenantID()

	// Create empty analysis output with metadata for tenant ID filename
	emptyAnalysisData := map[string]any{
		"metadata": map[string]any{
			"tenantId":   tenantID,
			"data_type": "azure_conditional_access_analysis",
			"status":    "analysis_failed",
		},
		"analysis": nil,
	}

	return emptyAnalysisData
}

// getTenantID retrieves the Azure tenant ID for filename generation
func (l *AzureConditionalAccessAnalysisOutputFormatterLink) getTenantID() (string, error) {
	// Get Azure credentials and create Graph client
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "unknown", err
	}
	
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return "unknown", err
	}
	
	// Get tenant info
	org, err := graphClient.Organization().Get(context.Background(), nil)
	if err != nil {
		return "unknown", err
	}
	
	if org != nil && org.GetValue() != nil && len(org.GetValue()) > 0 {
		if id := org.GetValue()[0].GetId(); id != nil {
			return *id, nil
		}
	}
	
	return "unknown", fmt.Errorf("no tenant ID available")
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

