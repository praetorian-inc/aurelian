package azure

import (
	"fmt"
	"path/filepath"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsOutputFormatterLink formats output with project-specific filenames
type AzureDevOpsOutputFormatterLink struct {
	*chain.Base
	projectName string
}

func NewAzureDevOpsOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsOutputFormatterLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
	}
}

func (l *AzureDevOpsOutputFormatterLink) Process(input any) error {
	// Check if this is a DevOpsScanConfig to capture project name
	if config, ok := input.(types.DevOpsScanConfig); ok {
		if config.Project != "" {
			l.projectName = config.Project
			l.Logger.Debug("Captured DevOps project name", "project", config.Project)
		}
		// Pass through the config unchanged
		l.Send(input)
		return nil
	}

	// For other types, wrap with named output data if we have a project name
	if l.projectName != "" {
		outputDir, _ := cfg.As[string](l.Arg("output"))
		if outputDir == "" {
			outputDir = "nebula-output"
		}

		filename := filepath.Join(outputDir, fmt.Sprintf("%s.json", l.projectName))
		namedOutput := outputters.NewNamedOutputData(input, filename)
		
		l.Logger.Debug("Wrapping output with project-specific filename", 
			"project", l.projectName, "filename", filename)
		
		l.Send(namedOutput)
	} else {
		// No project name captured, pass through unchanged
		l.Send(input)
	}

	return nil
}