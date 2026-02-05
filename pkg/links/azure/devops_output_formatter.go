package azure

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureDevOpsOutputFormatterLink formats output with project-specific filenames
type AzureDevOpsOutputFormatterLink struct {
	*base.NativeAzureLink
	projectName string
}

func NewAzureDevOpsOutputFormatterLink(args map[string]any) *AzureDevOpsOutputFormatterLink {
	return &AzureDevOpsOutputFormatterLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-devops-output-formatter", args),
	}
}

func (l *AzureDevOpsOutputFormatterLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.OutputDir(),
	}
}

func (l *AzureDevOpsOutputFormatterLink) Process(ctx context.Context, input any) ([]any, error) {
	// Check if this is a DevOpsScanConfig to capture project name
	if config, ok := input.(types.DevOpsScanConfig); ok {
		if config.Project != "" {
			l.projectName = config.Project
			l.Logger().Debug("Captured DevOps project name", "project", config.Project)
		}
		// Pass through the config unchanged
		l.Send(input)
		return l.Outputs(), nil
	}

	// For other types, wrap with named output data if we have a project name
	if l.projectName != "" {
		outputDir := l.ArgString("output", "aurelian-output")

		filename := filepath.Join(outputDir, fmt.Sprintf("%s.json", l.projectName))
		namedOutput := outputters.NewNamedOutputData(input, filename)

		l.Logger().Debug("Wrapping output with project-specific filename",
			"project", l.projectName, "filename", filename)

		l.Send(namedOutput)
	} else {
		// No project name captured, pass through unchanged
		l.Send(input)
	}

	return l.Outputs(), nil
}