package cmd

import (
	"io"

	"github.com/praetorian-inc/aurelian/pkg/outputters"
)

// OutputFormat constants
const (
	OutputFormatDefault  = "default"
	OutputFormatTerminal = "terminal"
	OutputFormatJSON     = "json"
	OutputFormatNDJSON   = "ndjson"
	OutputFormatMarkdown = "markdown"
	OutputFormatSARIF    = "sarif"
)

// SelectOutputter returns the appropriate outputter constructor based on format.
// Returns nil for "default" or unknown formats to indicate "use module default".
func SelectOutputter(format string) outputters.OutputterConstructor {
	return SelectOutputterWithWriter(format, nil)
}

// SelectOutputterWithWriter returns the appropriate outputter constructor based on format and writer.
// If writer is nil, defaults to os.Stdout.
// Returns nil for "default" or unknown formats to indicate "use module default".
func SelectOutputterWithWriter(format string, writer io.Writer) outputters.OutputterConstructor {
	switch format {
	case OutputFormatTerminal:
		return outputters.NewFormatterAdapterConstructor("terminal", writer)
	case OutputFormatJSON:
		return outputters.NewFormatterAdapterConstructor("json", writer)
	case OutputFormatNDJSON:
		return outputters.NewFormatterAdapterConstructor("ndjson", writer)
	case OutputFormatMarkdown:
		return outputters.NewFormatterAdapterConstructor("markdown", writer)
	case OutputFormatSARIF:
		return outputters.NewFormatterAdapterConstructor("sarif", writer)
	default:
		// Return nil to indicate "use module default"
		return nil
	}
}
