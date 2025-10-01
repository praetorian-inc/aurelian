package aws

import (
	"fmt"
	"strconv"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsResourceAggregatorLink collects AWS resources and outputs them with filename generation
type AwsResourceAggregatorLink struct {
	*chain.Base
	resources []types.EnrichedResourceDescription
}

func NewAwsResourceAggregatorLink(configs ...cfg.Config) chain.Link {
	l := &AwsResourceAggregatorLink{
		resources: make([]types.EnrichedResourceDescription, 0),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AwsResourceAggregatorLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AwsProfile(),
		cfg.NewParam[string]("filename", "Base filename for output").
			WithDefault("").
			WithShortcode("f"),
	}
}

func (l *AwsResourceAggregatorLink) Process(resource *types.EnrichedResourceDescription) error {
	l.resources = append(l.resources, *resource)
	l.Logger.Debug("Aggregated resource", "type", resource.TypeName, "id", resource.Identifier, "total", len(l.resources))
	return nil
}

func (l *AwsResourceAggregatorLink) Complete() error {
	profile, _ := cfg.As[string](l.Arg("profile"))
	filename, _ := cfg.As[string](l.Arg("filename"))

	l.Logger.Info("Aggregation complete", "total_resources", len(l.resources))

	// Generate filename if not provided
	if filename == "" {
		// Infer module type from resource types being aggregated
		moduleName := l.inferModuleName()
		filename = l.generateAWSFilename(moduleName, profile)
	}

	l.Logger.Info("Generated filename", "filename", filename, "profile", profile)

	// Send aggregated resources as named output
	outputData := outputters.NewNamedOutputData(l.resources, filename+".json")
	l.Send(outputData)

	return nil
}

// inferModuleName tries to determine the module type based on aggregated resources
func (l *AwsResourceAggregatorLink) inferModuleName() string {
	// Check if we have any resources to inspect
	if len(l.resources) == 0 {
		return "recon"
	}

	// Look at the first resource to see if it has specific attributes that suggest it's public resources
	firstResource := l.resources[0]

	// If the resource has PublicIp or other public-related properties, it's likely from public-resources
	if firstResource.Properties != nil {
		if properties, ok := firstResource.Properties.(map[string]interface{}); ok {
			if _, hasPublicIp := properties["PublicIp"]; hasPublicIp {
				return "public-resources"
			}
			// Check for other public-related indicators
			if _, hasPublicAccess := properties["PubliclyAccessible"]; hasPublicAccess {
				return "public-resources"
			}
		}
	}

	// Default to list-all for unknown cases
	return "list-all"
}

// generateAWSFilename creates AWS-specific filenames in format: {module-name}-{account}.json
func (l *AwsResourceAggregatorLink) generateAWSFilename(moduleName, profile string) string {
	// Try to get account ID but fail gracefully
	defer func() {
		if r := recover(); r != nil {
			l.Logger.Error("Panic in generateAWSFilename", "recover", r)
		}
	}()

	// For now, use profile name as fallback since AWS config setup is complex
	if profile != "" && profile != "default" {
		return fmt.Sprintf("%s-%s", moduleName, profile)
	}

	// Final fallback to timestamp
	return fmt.Sprintf("%s-%s", moduleName, strconv.FormatInt(time.Now().Unix(), 10))
}
