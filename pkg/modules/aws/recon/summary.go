package recon

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSSummaryModule{})
}

type SummaryConfig struct {
	plugin.AWSReconBase
	Days int `param:"days" desc:"Number of days to look back for cost data" default:"30" shortcode:"d"`
}

type AWSSummaryModule struct {
	SummaryConfig
}

func (m *AWSSummaryModule) ID() string                { return "summary" }
func (m *AWSSummaryModule) Name() string              { return "AWS Summary" }
func (m *AWSSummaryModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSSummaryModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSSummaryModule) OpsecLevel() string        { return "moderate" }
func (m *AWSSummaryModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSSummaryModule) Description() string {
	return "Use Cost Explorer to summarize the services and regions in use, displaying costs in a markdown table."
}

func (m *AWSSummaryModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cost-management/latest/userguide/ce-api.html",
	}
}

func (m *AWSSummaryModule) SupportedResourceTypes() []string {
	return []string{}
}

func (m *AWSSummaryModule) Parameters() any {
	return &m.SummaryConfig
}

func (m *AWSSummaryModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    m.Profile,
		ProfileDir: m.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("summary: load AWS config: %w", err)
	}

	client := costexplorer.NewFromConfig(awsCfg)
	ctx := context.TODO()

	days := m.Days
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	endDate := now.Format("2006-01-02")
	startDate := now.AddDate(0, 0, -days).Format("2006-01-02")

	slog.Info("querying Cost Explorer", "start", startDate, "end", endDate)

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: &startDate,
			End:   &endDate,
		},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"BlendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: strPtr("SERVICE")},
			{Type: cetypes.GroupDefinitionTypeDimension, Key: strPtr("REGION")},
		},
	}

	// Parse cost data into service -> region -> cost map.
	serviceRegions := make(map[string]map[string]float64)
	regionSet := make(map[string]bool)
	grandTotal := 0.0

	for {
		result, err := client.GetCostAndUsage(ctx, input)
		if err != nil {
			return fmt.Errorf("summary: Cost Explorer GetCostAndUsage: %w", err)
		}

		for _, rbt := range result.ResultsByTime {
			for _, group := range rbt.Groups {
				if len(group.Keys) < 2 {
					continue
				}
				service := cleanServiceName(group.Keys[0])
				region := group.Keys[1]
				if service == "" || region == "" {
					continue
				}

				var cost float64
				if metric, ok := group.Metrics["BlendedCost"]; ok && metric.Amount != nil {
					fmt.Sscanf(*metric.Amount, "%f", &cost)
				}

				if serviceRegions[service] == nil {
					serviceRegions[service] = make(map[string]float64)
				}
				serviceRegions[service][region] += cost
				regionSet[region] = true
				grandTotal += cost
			}
		}

		if result.NextPageToken == nil {
			break
		}
		input.NextPageToken = result.NextPageToken
	}

	slog.Info("cost summary", "services", len(serviceRegions), "total", fmt.Sprintf("$%.2f", grandTotal))

	// Build MarkdownTable output matching Nebula's format.
	table := buildCostTable(serviceRegions, regionSet, grandTotal, days)

	// Print markdown table to console.
	cfg.Info("\n%s", table.String())

	out.Send(table)
	return nil
}

func buildCostTable(serviceRegions map[string]map[string]float64, regionSet map[string]bool, grandTotal float64, days int) *output.AWSCostSummary {
	// Sort regions.
	regions := make([]string, 0, len(regionSet))
	for r := range regionSet {
		regions = append(regions, r)
	}
	sort.Strings(regions)

	// Sort services.
	services := make([]string, 0, len(serviceRegions))
	for s := range serviceRegions {
		services = append(services, s)
	}
	sort.Strings(services)

	// Headers: Service, region1, region2, ..., Total Cost
	headers := make([]string, 0, len(regions)+2)
	headers = append(headers, "Service")
	headers = append(headers, regions...)
	headers = append(headers, "Total Cost")

	// Rows: one per service + final TOTAL row.
	rows := make([][]string, 0, len(services)+1)
	totalByRegion := make(map[string]float64)

	for _, svc := range services {
		row := make([]string, 0, len(headers))
		row = append(row, svc)
		svcTotal := 0.0
		for _, r := range regions {
			cost := serviceRegions[svc][r]
			svcTotal += cost
			totalByRegion[r] += cost
			if cost > 0.01 {
				row = append(row, fmt.Sprintf("$%.2f", cost))
			} else {
				row = append(row, "-")
			}
		}
		row = append(row, fmt.Sprintf("$%.2f", svcTotal))
		rows = append(rows, row)
	}

	// TOTAL row with bold markdown formatting.
	totalRow := make([]string, 0, len(headers))
	totalRow = append(totalRow, "**TOTAL**")
	for _, r := range regions {
		if totalByRegion[r] > 0.01 {
			totalRow = append(totalRow, fmt.Sprintf("**$%.2f**", totalByRegion[r]))
		} else {
			totalRow = append(totalRow, "-")
		}
	}
	totalRow = append(totalRow, fmt.Sprintf("**$%.2f**", grandTotal))
	rows = append(rows, totalRow)

	return &output.AWSCostSummary{
		TableHeading: fmt.Sprintf("# AWS Cost Summary\n\nCost breakdown by service and region (last %d days):\n\n", days),
		Headers:      headers,
		Rows:         rows,
	}
}

func cleanServiceName(name string) string {
	name = strings.ReplaceAll(name, "Amazon ", "")
	name = strings.ReplaceAll(name, "AWS ", "")
	return name
}

func strPtr(s string) *string { return &s }
