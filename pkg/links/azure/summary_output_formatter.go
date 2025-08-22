package azure

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
	"path/filepath"
)

// AzureSummaryTable implements the Janus framework's Markdownable interface for console output
type AzureSummaryTable struct {
	env *helpers.AzureEnvironmentDetails
}

func (t *AzureSummaryTable) Columns() []string {
	return []string{"Resource Category", "Count"}
}

func (t *AzureSummaryTable) Rows() []int {
	// Group resources by category
	categories := make(map[string]int)
	for _, rc := range t.env.Resources {
		category := getResourceCategory(rc.ResourceType)
		categories[category] += rc.Count
	}
	
	// Create row indices (0-based)
	rows := make([]int, len(categories)+1) // +1 for total row
	for i := range rows {
		rows[i] = i
	}
	return rows
}

func (t *AzureSummaryTable) Values() []any {
	// Print header information to console first
	fmt.Printf("\n=== Azure Subscription Summary ===\n")
	fmt.Printf("Subscription: %s (%s)\n", t.env.SubscriptionName, t.env.SubscriptionID)
	fmt.Printf("Tenant: %s (%s)\n", t.env.TenantName, t.env.TenantID)
	fmt.Printf("State: %s\n", t.env.State)
	
	if t.env.Tags != nil && len(t.env.Tags) > 0 {
		var tagStrings []string
		for k, v := range t.env.Tags {
			if v != "" {
				tagStrings = append(tagStrings, fmt.Sprintf("%s: %s", k, v))
			}
		}
		if len(tagStrings) > 0 {
			fmt.Printf("Tags: %s\n", strings.Join(tagStrings, ", "))
		}
	}
	
	// Group resources by category and calculate totals
	categories := make(map[string]int)
	for _, rc := range t.env.Resources {
		category := getResourceCategory(rc.ResourceType)
		categories[category] += rc.Count
	}

	// Sort categories
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)
	
	totalCount := 0
	for _, count := range categories {
		totalCount += count
	}

	// Print console table format immediately
	fmt.Printf("\nResource Summary:\n")
	fmt.Printf("| %-20s | %5s |\n", "Resource Category", "Count")
	fmt.Printf("| %-20s | %5s |\n", strings.Repeat("-", 20), strings.Repeat("-", 5))
	
	for _, category := range categoryNames {
		count := categories[category]
		fmt.Printf("| %-20s | %5d |\n", category, count)
	}
	fmt.Printf("| %-20s | %5s |\n", strings.Repeat("-", 20), strings.Repeat("-", 5))
	fmt.Printf("| %-20s | %5d |\n", "Total", totalCount)
	fmt.Printf("\n")

	// Return empty values since we're handling console output directly
	// The Janus markdown outputter will still create the file output
	return []any{}
}

// AzureSummaryOutputFormatterLink formats Azure environment details into JSON and Markdown outputs
type AzureSummaryOutputFormatterLink struct {
	*chain.Base
	envDetails []*helpers.AzureEnvironmentDetails
}

func NewAzureSummaryOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &AzureSummaryOutputFormatterLink{
		envDetails: make([]*helpers.AzureEnvironmentDetails, 0),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureSummaryOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
		cfg.NewParam[string]("filename", "Base filename for output").
			WithDefault("").
			WithShortcode("f"),
	}
}

func (l *AzureSummaryOutputFormatterLink) Process(input any) error {
	switch v := input.(type) {
	case *helpers.AzureEnvironmentDetails:
		l.envDetails = append(l.envDetails, v)
		l.Logger.Debug("Collected environment details", "subscription", v.SubscriptionID, "resource_types", len(v.Resources))
	default:
		l.Logger.Debug("Received unknown input type", "type", fmt.Sprintf("%T", input))
	}
	
	return nil
}

func (l *AzureSummaryOutputFormatterLink) Complete() error {
	l.Logger.Info("Formatting outputs", "environment_count", len(l.envDetails))
	
	// Process each environment details
	for _, env := range l.envDetails {
		l.generateOutput(env)
	}
	
	return nil
}

func (l *AzureSummaryOutputFormatterLink) generateOutput(env *helpers.AzureEnvironmentDetails) {
	// Get output directory
	outputDir, _ := cfg.As[string](l.Arg("output"))
	
	// Generate base filename
	baseFilename, _ := cfg.As[string](l.Arg("filename"))
	if baseFilename == "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		baseFilename = fmt.Sprintf("summary-%s-%s", env.SubscriptionID, timestamp)
	} else {
		baseFilename = baseFilename + "-" + env.SubscriptionID
	}
	
	l.Logger.Info("Generated filename", "filename", baseFilename, "subscription", env.SubscriptionID, "output_dir", outputDir)
	
	// Convert to EnrichedResourceDescription format for JSON
	var resources []types.EnrichedResourceDescription
	for _, rc := range env.Resources {
		resources = append(resources, types.EnrichedResourceDescription{
			Identifier: rc.ResourceType,
			TypeName:   rc.ResourceType,
			Region:     "", // Azure regions are handled differently
			AccountId:  env.SubscriptionID,
			Properties: map[string]interface{}{
				"count":    rc.Count,
				"provider": getResourceCategory(rc.ResourceType),
			},
		})
	}
	
	// Create full path with output directory
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
	
	// Send JSON output
	jsonOutputData := outputters.NewNamedOutputData(resources, jsonFilePath)
	l.Send(jsonOutputData)
	
	// Create and send Janus-compatible markdown table for console output
	summaryTable := &AzureSummaryTable{env: env}
	l.Send(summaryTable)
}

// Helper function to categorize Azure resources
func getResourceCategory(resourceType string) string {
	parts := strings.Split(resourceType, "/")
	if len(parts) > 0 {
		provider := parts[0]
		provider = strings.TrimPrefix(provider, "Microsoft.")
		return provider
	}
	return resourceType
}

// Helper function to create summary table
func (l *AzureSummaryOutputFormatterLink) createSummaryTable(env *helpers.AzureEnvironmentDetails) types.MarkdownTable {
	// Create subscription overview section
	var details []string
	details = append(details, fmt.Sprintf("# Azure Subscription Summary"))
	details = append(details, fmt.Sprintf("Subscription: %s (%s)", env.SubscriptionName, env.SubscriptionID))
	details = append(details, fmt.Sprintf("Tenant: %s (%s)", env.TenantName, env.TenantID))
	if env.Tags != nil && len(env.Tags) > 0 {
		var tagStrings []string
		for k, v := range env.Tags {
			if v != "" {
				tagStrings = append(tagStrings, fmt.Sprintf("%s: %s", k, v))
			}
		}
		if len(tagStrings) > 0 {
			details = append(details, "Tags: "+strings.Join(tagStrings, ", "))
		}
	}
	details = append(details, "")

	// Group resources by category
	categories := make(map[string]int)
	for _, rc := range env.Resources {
		category := getResourceCategory(rc.ResourceType)
		categories[category] += rc.Count
	}

	// Sort categories
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	// Create table
	table := types.MarkdownTable{
		TableHeading: strings.Join(details, "\\n"),
		Headers:      []string{"Resource Category", "Count"},
		Rows:         make([][]string, 0),
	}

	totalCount := 0
	for _, category := range categoryNames {
		count := categories[category]
		table.Rows = append(table.Rows, []string{
			category,
			fmt.Sprintf("%d", count),
		})
		totalCount += count
	}

	// Add total row
	table.Rows = append(table.Rows, []string{"Total", fmt.Sprintf("%d", totalCount)})

	return table
}