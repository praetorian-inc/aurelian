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

	result, err := client.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
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
	})
	if err != nil {
		return fmt.Errorf("summary: Cost Explorer GetCostAndUsage: %w", err)
	}

	serviceRegions := make(map[string]map[string]float64)
	grandTotal := 0.0

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
			grandTotal += cost
		}
	}

	slog.Info("cost summary", "services", len(serviceRegions), "total", fmt.Sprintf("$%.2f", grandTotal))

	if cfg.Verbose {
		printSummaryTable(serviceRegions, grandTotal)
	}

	out.Send(&output.AWSCostSummary{
		Services:  serviceRegions,
		TotalCost: grandTotal,
		Days:      days,
	})
	return nil
}

func cleanServiceName(name string) string {
	name = strings.ReplaceAll(name, "Amazon ", "")
	name = strings.ReplaceAll(name, "AWS ", "")
	return name
}

func strPtr(s string) *string { return &s }

func printSummaryTable(serviceRegions map[string]map[string]float64, grandTotal float64) {
	// Collect all regions
	regionSet := make(map[string]bool)
	for _, regions := range serviceRegions {
		for r := range regions {
			regionSet[r] = true
		}
	}
	var regions []string
	for r := range regionSet {
		regions = append(regions, r)
	}
	sort.Strings(regions)

	// Sort services
	var services []string
	for s := range serviceRegions {
		services = append(services, s)
	}
	sort.Strings(services)

	// Print header
	fmt.Printf("\n%-40s", "Service")
	for _, r := range regions {
		fmt.Printf("  %-16s", r)
	}
	fmt.Printf("  %-12s\n", "Total")
	fmt.Println(strings.Repeat("-", 40+18*len(regions)+14))

	// Print rows
	for _, svc := range services {
		svcTotal := 0.0
		fmt.Printf("%-40s", svc)
		for _, r := range regions {
			cost := serviceRegions[svc][r]
			svcTotal += cost
			if cost > 0.01 {
				fmt.Printf("  $%-15.2f", cost)
			} else {
				fmt.Printf("  %-16s", "-")
			}
		}
		fmt.Printf("  $%-11.2f\n", svcTotal)
	}

	fmt.Println(strings.Repeat("-", 40+18*len(regions)+14))
	fmt.Printf("%-40s", "TOTAL")
	totalByRegion := make(map[string]float64)
	for _, regions := range serviceRegions {
		for r, cost := range regions {
			totalByRegion[r] += cost
		}
	}
	for _, r := range regions {
		if totalByRegion[r] > 0.01 {
			fmt.Printf("  $%-15.2f", totalByRegion[r])
		} else {
			fmt.Printf("  %-16s", "-")
		}
	}
	fmt.Printf("  $%-11.2f\n\n", grandTotal)
}
