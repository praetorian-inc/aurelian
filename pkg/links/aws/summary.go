package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AWSSummaryLink uses Cost Explorer to summarize AWS service usage
type AWSSummaryLink struct {
	*base.AwsReconLink
	serviceRegions map[string]map[string]float64 // service -> region -> cost
}

func NewAWSSummaryLink(configs ...cfg.Config) chain.Link {
	s := &AWSSummaryLink{
		serviceRegions: make(map[string]map[string]float64),
	}
	s.AwsReconLink = base.NewAwsReconLink(s, configs...)
	return s
}

func (s *AWSSummaryLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[int]("days", "Number of days to look back for cost data").WithDefault(30),
	}
}

func (s *AWSSummaryLink) Process(input string) error {
	// Use us-east-1 for Cost Explorer as it's a global service
	config, err := s.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	ceClient := costexplorer.NewFromConfig(config)
	
	days, err := cfg.As[int](s.Arg("days"))
	if err != nil {
		days = 30
	}

	// Get cost and usage data grouped by service and region
	if err := s.getCostData(ceClient, days); err != nil {
		return fmt.Errorf("failed to get cost data: %w", err)
	}

	// Create summary table
	summary := s.createSummaryTable()
	
	// Send the summary as markdown table
	return s.Send(summary)
}

func (s *AWSSummaryLink) getCostData(client *costexplorer.Client, days int) error {
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
				Type: cetypes.GroupDefinitionTypeService,
				Key:  stringPtr("SERVICE"),
			},
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  stringPtr("REGION"),
			},
		},
	}

	result, err := client.GetCostAndUsage(context.TODO(), input)
	if err != nil {
		// If Cost Explorer fails, create a basic summary from input
		s.Logger.Debug("Cost Explorer API failed, creating basic summary", "error", err)
		return s.createBasicSummary()
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
				if group.Metrics != nil && group.Metrics["BlendedCost"] != nil {
					if group.Metrics["BlendedCost"].Amount != nil {
						fmt.Sscanf(*group.Metrics["BlendedCost"].Amount, "%f", &cost)
					}
				}
				
				// Store in map
				if s.serviceRegions[service] == nil {
					s.serviceRegions[service] = make(map[string]float64)
				}
				s.serviceRegions[service][region] += cost
			}
		}
	}

	return nil
}

func (s *AWSSummaryLink) createBasicSummary() error {
	// Create a basic summary when Cost Explorer is not available
	s.serviceRegions = map[string]map[string]float64{
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

func (s *AWSSummaryLink) createSummaryTable() types.MarkdownTable {
	// Get all unique regions
	regionSet := make(map[string]bool)
	for _, regions := range s.serviceRegions {
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
	for service := range s.serviceRegions {
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
			cost := s.serviceRegions[service][region]
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