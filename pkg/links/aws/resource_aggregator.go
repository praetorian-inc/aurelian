package aws

import (
	"fmt"
	"strconv"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
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
		config, err := helpers.GetAWSCfg("", profile, nil)
		if err != nil {
			l.Logger.Error("Error getting AWS config", "error", err)
			filename = fmt.Sprintf("list-all-%s-%s", profile, strconv.FormatInt(time.Now().Unix(), 10))
		} else {
			accountId, err := helpers.GetAccountId(config)
			if err != nil {
				l.Logger.Error("Error getting account ID", "error", err)
				accountId = "unknown"
			}
			
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			filename = fmt.Sprintf("list-all-%s-%s-%s", profile, accountId, timestamp)
		}
	}
	
	l.Logger.Info("Generated filename", "filename", filename, "profile", profile)
	
	// Send aggregated resources as named output
	outputData := outputters.NewNamedOutputData(l.resources, filename+".json")
	l.Send(outputData)
	
	return nil
}