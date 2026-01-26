package hierarchy

import (
	"fmt"
	"path/filepath"
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
	*chain.Base
	envDetails []*helpers.GCPEnvironmentDetails
}

// link to format GCP details into JSON and MD
func NewGcpSummaryOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &GcpSummaryOutputFormatterLink{
		envDetails: make([]*helpers.GCPEnvironmentDetails, 0),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *GcpSummaryOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
		cfg.NewParam[string]("filename", "Base filename for output").WithDefault("").WithShortcode("f"),
	}
}

func (l *GcpSummaryOutputFormatterLink) Process(input any) error {
	switch v := input.(type) {
	case *helpers.GCPEnvironmentDetails:
		l.envDetails = append(l.envDetails, v)
		l.Logger.Debug("Collected environment details", "scope", v.ScopeID, "resource_types", len(v.Resources))
	default:
		l.Logger.Debug("Received unknown input type", "type", fmt.Sprintf("%T", input))
	}
	return nil
}

func (l *GcpSummaryOutputFormatterLink) Complete() error {
	l.Logger.Info("Formatting outputs", "environment_count", len(l.envDetails))
	for _, env := range l.envDetails {
		l.generateOutput(env)
	}
	return nil
}

func (l *GcpSummaryOutputFormatterLink) generateOutput(env *helpers.GCPEnvironmentDetails) {
	outputDir, _ := cfg.As[string](l.Arg("output"))
	baseFilename, _ := cfg.As[string](l.Arg("filename"))
	if baseFilename == "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		baseFilename = fmt.Sprintf("summary-%s-%s", env.ScopeID, timestamp)
	} else {
		baseFilename = baseFilename + "-" + env.ScopeID
	}
	l.Logger.Info("Generated filename", "filename", baseFilename, "scope", env.ScopeID, "output_dir", outputDir)
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
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
	jsonOutputData := outputters.NewNamedOutputData(outputData, jsonFilePath)
	l.Send(jsonOutputData)
	table := l.createSummaryTable(env, summary, totalCount)
	l.Send(table)
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
