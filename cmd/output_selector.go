package cmd

import (
	"io"

	"github.com/praetorian-inc/aurelian/pkg/outputters"
)

const (
	OutputFormatDefault  = "default"
	OutputFormatTerminal = "terminal"
	OutputFormatJSON     = "json"
	OutputFormatNDJSON   = "ndjson"
	OutputFormatMarkdown = "markdown"
	OutputFormatSARIF    = "sarif"
)

func SelectOutputter(format string) outputters.OutputterConstructor {
	return SelectOutputterWithWriter(format, nil)
}

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
