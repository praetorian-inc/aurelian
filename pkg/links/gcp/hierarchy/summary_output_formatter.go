package hierarchy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

type GcpResourceSummary struct {
	AssetType string `json:"asset_type"`
	Category  string `json:"category"`
	Count     int    `json:"count"`
}

type GcpSummaryOutput struct {
	ScopeType string               `json:"scope_type"`
	ScopeName string               `json:"scope_name"`
	ScopeID   string               `json:"scope_id"`
	Location  string               `json:"location,omitempty"`
	Labels    map[string]string    `json:"labels,omitempty"`
	Resources []GcpResourceSummary `json:"resources"`
	Summary   map[string]int       `json:"summary"`
	Total     int                  `json:"total"`
}

type GcpSummaryOutputFormatterLink struct {
	*base.NativeGCPLink
	envDetails []*helpers.GCPEnvironmentDetails
	outputDir  string
	filename   string
}

// link to format GCP details into JSON and MD
func NewGcpSummaryOutputFormatterLink(args map[string]any) *GcpSummaryOutputFormatterLink {
	link := &GcpSummaryOutputFormatterLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-summary-output-formatter", args),
		envDetails:    make([]*helpers.GCPEnvironmentDetails, 0),
	}
	link.outputDir = link.ArgString("output", "")
	link.filename = link.ArgString("filename", "")
	return link
}

func (l *GcpSummaryOutputFormatterLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("output", "Output directory for generated files"),
		plugin.NewParam[string]("filename", "Base filename for output", plugin.WithShortcode("f")),
	)
	return params
}

func (l *GcpSummaryOutputFormatterLink) Process(ctx context.Context, input any) ([]any, error) {
	switch v := input.(type) {
	case *helpers.GCPEnvironmentDetails:
		l.envDetails = append(l.envDetails, v)
		slog.Debug("Collected environment details", "scope", v.ScopeID, "resource_types", len(v.Resources))
	default:
		slog.Debug("Received unknown input type", "type", fmt.Sprintf("%T", input))
	}
	return nil, nil
}

func (l *GcpSummaryOutputFormatterLink) Complete(ctx context.Context) error {
	slog.Info("Formatting outputs", "environment_count", len(l.envDetails))
	for _, env := range l.envDetails {
		if err := l.generateOutput(env); err != nil {
			return err
		}
	}
	return nil
}

func (l *GcpSummaryOutputFormatterLink) generateOutput(env *helpers.GCPEnvironmentDetails) error {
	baseFilename := l.filename
	if baseFilename == "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		baseFilename = fmt.Sprintf("summary-%s-%s", env.ScopeID, timestamp)
	} else {
		baseFilename = baseFilename + "-" + env.ScopeID
	}
	slog.Info("Generated filename", "filename", baseFilename, "scope", env.ScopeID, "output_dir", l.outputDir)

	var resources []GcpResourceSummary
	summary := make(map[string]int)
	totalCount := 0
	for _, rc := range env.Resources {
		category := getResourceCategory(rc.ResourceType)
		resources = append(resources, GcpResourceSummary{
			AssetType: rc.ResourceType,
			Category:  category,
			Count:     rc.Count,
		})
		summary[category] += rc.Count
		totalCount += rc.Count
	}
	outputData := GcpSummaryOutput{
		ScopeType: env.ScopeType,
		ScopeName: env.ScopeName,
		ScopeID:   env.ScopeID,
		Location:  env.Location,
		Labels:    env.Labels,
		Resources: resources,
		Summary:   summary,
		Total:     totalCount,
	}

	// Write JSON output
	jsonFilePath := filepath.Join(l.outputDir, baseFilename+".json")
	if err := utils.EnsureFileDirectory(jsonFilePath); err != nil {
		return fmt.Errorf("failed to create directory for JSON output: %w", err)
	}
	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON data: %w", err)
	}
	if err := os.WriteFile(jsonFilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}
	slog.Info("Wrote JSON output", "file", jsonFilePath)

	// Write Markdown table
	table := l.createSummaryTable(env, summary, totalCount)
	mdFilePath := filepath.Join(l.outputDir, baseFilename+".md")
	if err := utils.EnsureFileDirectory(mdFilePath); err != nil {
		return fmt.Errorf("failed to create directory for Markdown output: %w", err)
	}
	mdContent := table.ToString()
	if err := os.WriteFile(mdFilePath, []byte(mdContent), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown output: %w", err)
	}
	slog.Info("Wrote Markdown output", "file", mdFilePath)

	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func getResourceCategory(assetType string) string {
	// extract from cloud resource type format not using the tabularium type
	parts := strings.Split(assetType, "/")
	if len(parts) > 0 {
		serviceParts := strings.Split(parts[0], ".")
		if len(serviceParts) > 0 {
			service := serviceParts[0]
			// capitalizing first letter for simplicity
			if len(service) > 0 {
				service = strings.ToUpper(service[:1]) + service[1:]
			}
			return service
		}
	}
	return assetType
}

func (l *GcpSummaryOutputFormatterLink) createSummaryTable(env *helpers.GCPEnvironmentDetails, summary map[string]int, totalCount int) types.MarkdownTable {
	var details []string
	details = append(details, fmt.Sprintf("# GCP %s Summary", strings.Title(env.ScopeType)))
	details = append(details, "")
	details = append(details, fmt.Sprintf("%s: %s (%s)", strings.Title(env.ScopeType), env.ScopeName, env.ScopeID))
	if env.Location != "" {
		details = append(details, fmt.Sprintf("Location: %s", env.Location))
	}
	if env.Labels != nil && len(env.Labels) > 0 {
		var labelStrings []string
		for k, v := range env.Labels {
			if v != "" {
				labelStrings = append(labelStrings, fmt.Sprintf("%s=%s", k, v))
			}
		}
		if len(labelStrings) > 0 {
			details = append(details, "Labels: "+strings.Join(labelStrings, ", "))
		}
	}

	var categoryNames []string
	for category := range summary {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)
	var rows [][]string
	for _, category := range categoryNames {
		count := summary[category]
		rows = append(rows, []string{
			category,
			fmt.Sprintf("%d", count),
		})
	}
	rows = append(rows, []string{"**TOTAL**", fmt.Sprintf("**%d**", totalCount)})
	return types.MarkdownTable{
		TableHeading: strings.Join(details, "\n") + "\n\nResource breakdown by category:\n",
		Headers:      []string{"Category", "Count"},
		Rows:         rows,
	}
}
