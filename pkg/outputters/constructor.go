package outputters

import (
	"io"
	"os"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// OutputterConstructor is a function that creates a plugin.Outputter.
// This replaces the janus-framework chain.OutputterConstructor type.
type OutputterConstructor func() plugin.Outputter

// NewFormatterAdapterConstructor creates a constructor that returns a FormatterAdapter
// wrapping a formatter of the specified format type.
//
// format: one of "terminal", "json", "ndjson", "markdown", "sarif"
// writer: optional io.Writer (defaults to os.Stdout if nil)
//
// This function exists to support the cmd package's output format selection.
func NewFormatterAdapterConstructor(format string, writer io.Writer) OutputterConstructor {
	return func() plugin.Outputter {
		if writer == nil {
			writer = os.Stdout
		}

		// Map format string to formatter.Format constant
		var fmtType formatter.Format
		switch format {
		case "terminal":
			fmtType = formatter.FormatTerminal
		case "json":
			fmtType = formatter.FormatJSON
		case "ndjson":
			fmtType = formatter.FormatNDJSON
		case "markdown":
			fmtType = formatter.FormatMarkdown
		case "sarif":
			fmtType = formatter.FormatSARIF
		default:
			// Fallback to terminal for unknown formats
			fmtType = formatter.FormatTerminal
		}

		// Create formatter using capability-sdk factory
		f, err := formatter.New(formatter.Config{
			Format: fmtType,
			Writer: writer,
		})
		if err != nil {
			// If formatter creation fails, return a no-op outputter
			// This shouldn't happen in practice since we control the format strings
			return &noOpOutputter{}
		}

		return NewFormatterAdapter(f, writer)
	}
}

// noOpOutputter is a fallback outputter that does nothing.
// Used only if formatter creation fails unexpectedly.
type noOpOutputter struct{}

func (n *noOpOutputter) Initialize(cfg plugin.Config) error { return nil }
func (n *noOpOutputter) Output(val any) error               { return nil }
func (n *noOpOutputter) Complete() error                    { return nil }
