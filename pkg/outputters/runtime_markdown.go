package outputters

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

const defaultMDOutfile = "out.md"

// RuntimeMarkdownOutputter allows specifying the output file at runtime
type RuntimeMarkdownOutputter struct {
	cfg     plugin.Config
	outfile string
	results map[string][]string
}

// NewRuntimeMarkdownOutputter creates a new RuntimeMarkdownOutputter
//
// Deprecated: Use outputters.NewFormatterAdapterConstructor(formatter.FormatMarkdown, writer) instead.
// This outputter will be removed in v2.0.
func NewRuntimeMarkdownOutputter() *RuntimeMarkdownOutputter {
	return &RuntimeMarkdownOutputter{
		results: make(map[string][]string),
	}
}

func (m *RuntimeMarkdownOutputter) Initialize(cfg plugin.Config) error {
	m.cfg = cfg
	outfile := plugin.GetArgOrDefault(cfg, "mdoutfile", defaultMDOutfile)
	m.outfile = outfile
	slog.Debug("initialized runtime Markdown outputter", "default_file", m.outfile)
	return nil
}

func (m *RuntimeMarkdownOutputter) Output(val any) error {
	if outputData, ok := val.(NamedOutputData); ok {
		if outputData.OutputFilename != "" && m.outfile == defaultMDOutfile {
			m.SetOutputFile(outputData.OutputFilename)
		}

		if table, ok := outputData.Data.(types.MarkdownTable); ok {
			m.results[m.outfile] = append(m.results[m.outfile], table.ToString())
		}
	}
	return nil
}

func (m *RuntimeMarkdownOutputter) SetOutputFile(filename string) {
	m.outfile = filename
	slog.Debug("changed Markdown output file", "filename", filename)
}

func (m *RuntimeMarkdownOutputter) Complete() error {
	for fname, contents := range m.results {
		slog.Debug("writing Markdown output", "filename", fname, "tables", len(contents))
		f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error creating Markdown file %s: %w", fname, err)
		}
		defer f.Close()

		for _, content := range contents {
			if _, err := f.WriteString(content + "\n\n"); err != nil {
				return fmt.Errorf("error writing to Markdown file %s: %w", fname, err)
			}
		}
	}
	return nil
}

