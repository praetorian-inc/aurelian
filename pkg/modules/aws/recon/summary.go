package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry" 
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

var AwsSummary = chain.NewModule(
	cfg.NewMetadata(
		"AWS Summary",
		"Use Cost Explorer to summarize the services and regions in use, displaying costs in a markdown table.",
	).WithProperties(map[string]any{
		"id":          "summary",
		"platform":    "aws",
		"opsec_level": "moderate", 
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/cost-management/latest/userguide/ce-api.html",
			"https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/ce-what-is.html",
		},
	}),
).WithLinks(
	// Generate a single input to trigger the summary
	aws.NewAwsResourceTypeGeneratorLink,
	// Create the cost summary using Cost Explorer
	aws.NewAWSSummaryLink,
).WithOutputters(
	// Output as markdown table for console display
	output.NewMarkdownOutputter,
	// Also output as JSON for programmatic use
	output.NewJSONOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	cfg.NewParam[int]("days", "Number of days to look back for cost data").
		WithDefault(30).
		WithShortcode("d"),
).WithInputParam(
	cfg.NewParam[string]("filename", "Base filename for output").
		WithDefault("aws-summary").
		WithShortcode("f"),
).WithAutoRun()

func init() {
	registry.Register("aws", "recon", "summary", *AwsSummary)
}