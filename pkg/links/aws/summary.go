package aws

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AWSSummaryLink uses Cost Explorer to summarize AWS service usage
type AWSSummaryLink struct {
	*base.NativeAWSLink
	serviceRegions map[string]map[string]float64 // service -> region -> cost
}

func NewAWSSummaryLink(args map[string]any) *AWSSummaryLink {
	return &AWSSummaryLink{
		NativeAWSLink:  base.NewNativeAWSLink("AWSSummaryLink", args),
		serviceRegions: make(map[string]map[string]float64),
	}
}

func (s *AWSSummaryLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[int]("days", "Number of days to look back for cost data"),
	}
}

// Process implements the plugin interface
func (s *AWSSummaryLink) Process(ctx context.Context, input any) ([]any, error) {
	// TODO: Port Janus chain logic to standalone implementation
	s.Logger().Info("AWSSummaryLink.Process not yet implemented - requires Janus removal")
	return s.Outputs(), nil
}
