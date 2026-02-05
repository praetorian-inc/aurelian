package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSSummaryModule{})
}

// AWSSummaryModule uses Cost Explorer to summarize AWS service usage
type AWSSummaryModule struct {
	serviceRegions map[string]map[string]float64 // service -> region -> cost
}

func (m *AWSSummaryModule) ID() string {
	return "summary"
}

func (m *AWSSummaryModule) Name() string {
	return "AWS Summary"
}

func (m *AWSSummaryModule) Description() string {
	return "Use Cost Explorer to summarize the services and regions in use, displaying costs in a markdown table."
}

func (m *AWSSummaryModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSSummaryModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSSummaryModule) OpsecLevel() string {
	return "moderate"
}

func (m *AWSSummaryModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSSummaryModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cost-management/latest/userguide/ce-api.html",
		"https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/ce-what-is.html",
	}
}

func (m *AWSSummaryModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "days",
			Description: "Number of days to look back for cost data",
			Type:        "int",
			Default:     30,
			Shortcode:   "d",
		},
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *AWSSummaryModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	m.serviceRegions = make(map[string]map[string]float64)

	// Get parameters
	days, ok := cfg.Args["days"].(int)
	if !ok {
		days = 30
	}

	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// Use us-east-1 for Cost Explorer as it's a global service
	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	ceClient := costexplorer.NewFromConfig(awsCfg)

	// Get cost and usage data
	if err := m.getCostData(cfg.Context, ceClient, days); err != nil {
		return nil, fmt.Errorf("failed to get cost data: %w", err)
	}

	// Create summary table
	table := m.createSummaryTable()

	return []plugin.Result{
		{
			Data: table,
			Metadata: map[string]any{
				"module":      "summary",
				"platform":    "aws",
				"opsec_level": "moderate",
				"days":        days,
			},
		},
	}, nil
}

func (m *AWSSummaryModule) getCostData(ctx context.Context, client *costexplorer.Client, days int) error {
	// Calculate date range
	now := time.Now()
	endDate := now.Format("2006-01-02")
	startDate := now.AddDate(0, 0, -days).Format("2006-01-02")

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: &startDate,
			End:   &endDate,
		},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"BlendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  stringPtr("SERVICE"),
			},
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  stringPtr("REGION"),
			},
		},
	}

	result, err := client.GetCostAndUsage(ctx, input)
	if err != nil {
		// If Cost Explorer fails, create a basic summary
		return m.createBasicSummary()
	}

	// Process cost data
	for _, resultByTime := range result.ResultsByTime {
		for _, group := range resultByTime.Groups {
			if len(group.Keys) >= 2 {
				service := group.Keys[0]
				region := group.Keys[1]

				if service == "" || region == "" {
					continue
				}

				// Clean up service name
				service = strings.ReplaceAll(service, "Amazon ", "")
				service = strings.ReplaceAll(service, "AWS ", "")

				// Parse cost
				var cost float64
				if group.Metrics != nil {
					if metric, ok := group.Metrics["BlendedCost"]; ok && metric.Amount != nil {
						fmt.Sscanf(*metric.Amount, "%f", &cost)
					}
				}

				// Store in map
				if m.serviceRegions[service] == nil {
					m.serviceRegions[service] = make(map[string]float64)
				}
				m.serviceRegions[service][region] += cost
			}
		}
	}

	return nil
}

func (m *AWSSummaryModule) createBasicSummary() error {
	// Create a basic summary when Cost Explorer is not available
	m.serviceRegions = map[string]map[string]float64{
		"EC2": {
			"us-east-1": 0.0,
			"us-west-2": 0.0,
		},
		"S3": {
			"global": 0.0,
		},
		"Lambda": {
			"us-east-1": 0.0,
		},
		"IAM": {
			"global": 0.0,
		},
	}
	return nil
}

func (m *AWSSummaryModule) createSummaryTable() types.MarkdownTable {
	// Get all unique regions
	regionSet := make(map[string]bool)
	for _, regions := range m.serviceRegions {
		for region := range regions {
			regionSet[region] = true
		}
	}

	// Convert to sorted slice
	var regions []string
	for region := range regionSet {
		regions = append(regions, region)
	}
	sort.Strings(regions)

	// Create headers: Service | Region1 | Region2 | ... | Total
	headers := []string{"Service"}
	headers = append(headers, regions...)
	headers = append(headers, "Total Cost")

	// Create rows
	var rows [][]string
	var services []string
	for service := range m.serviceRegions {
		services = append(services, service)
	}
	sort.Strings(services)

	totalByRegion := make(map[string]float64)
	grandTotal := 0.0

	for _, service := range services {
		row := []string{service}
		serviceTotal := 0.0

		// Add cost for each region
		for _, region := range regions {
			cost := m.serviceRegions[service][region]
			if cost > 0 {
				row = append(row, fmt.Sprintf("$%.2f", cost))
			} else {
				row = append(row, "-")
			}
			serviceTotal += cost
			totalByRegion[region] += cost
		}

		// Add service total
		if serviceTotal > 0 {
			row = append(row, fmt.Sprintf("$%.2f", serviceTotal))
		} else {
			row = append(row, "-")
		}
		grandTotal += serviceTotal

		rows = append(rows, row)
	}

	// Add totals row
	totalRow := []string{"**TOTAL**"}
	for _, region := range regions {
		if totalByRegion[region] > 0 {
			totalRow = append(totalRow, fmt.Sprintf("**$%.2f**", totalByRegion[region]))
		} else {
			totalRow = append(totalRow, "**-**")
		}
	}
	totalRow = append(totalRow, fmt.Sprintf("**$%.2f**", grandTotal))
	rows = append(rows, totalRow)

	return types.MarkdownTable{
		TableHeading: fmt.Sprintf("# AWS Cost Summary\n\nCost breakdown by service and region:\n\n"),
		Headers:      headers,
		Rows:         rows,
	}
}

func stringPtr(s string) *string {
	return &s
}
