package outputters

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

const defaultMDOutfile = "out.md"

// RuntimeMarkdownOutputter allows specifying the output file at runtime
type RuntimeMarkdownOutputter struct {
	*chain.BaseOutputter
	outfile string
	results map[string][]string
}

// NewRuntimeMarkdownOutputter creates a new RuntimeMarkdownOutputter
func NewRuntimeMarkdownOutputter(configs ...cfg.Config) chain.Outputter {
	m := &RuntimeMarkdownOutputter{
		results: make(map[string][]string),
	}
	m.BaseOutputter = chain.NewBaseOutputter(m, configs...)
	return m
}

func (m *RuntimeMarkdownOutputter) Initialize() error {
	outfile, err := cfg.As[string](m.Arg("mdoutfile"))
	if err != nil {
		outfile = defaultMDOutfile // Fallback default
	}
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

func (m *RuntimeMarkdownOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("mdoutfile", "the default file to write the Markdown to (can be changed at runtime)").WithDefault(defaultMDOutfile),
	}
}
