package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AWSCostSummary represents a Cost Explorer breakdown of services and regions.
type AWSCostSummary struct {
	model.BaseAurelianModel

	// Services maps service name -> region -> cost.
	Services map[string]map[string]float64 `json:"services"`

	// TotalCost is the grand total across all services and regions.
	TotalCost float64 `json:"total_cost"`

	// Days is the lookback window used.
	Days int `json:"days"`
}
