package outputproviders

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/nebula/internal/message"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type MarkdownFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewMarkdownFileProvider(opts []*types.Option) types.OutputProvider {
	return &MarkdownFileProvider{
		OutputPath: options.GetOptionByName(options.OutputOpt.Name, opts).Value,
		FileName:   "",
	}
}

func (fp *MarkdownFileProvider) Write(result types.Result) error {
	// Result.Data needs to be of type MarkdownTable for this provider to work
	table, ok := result.Data.(types.MarkdownTable)
	if !ok {
		return nil
	}
	var filename string
	if result.Filename == "" {
		filename = fp.DefaultFileName(result.Module)
	} else {
		filename = result.Filename
	}
	fullpath := GetFullPath(filename, fp.OutputPath)
	dir := filepath.Dir(fullpath)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	file, err := os.OpenFile(fullpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write table heading if exists
	if table.TableHeading != "" {
		file.WriteString("# " + table.TableHeading + "\n\n")
	}

	// Dynamically determine column width
	colWidths := make([]int, len(table.Headers))
	for i, header := range table.Headers {
		colWidths[i] = len(header)
	}
	for _, row := range table.Rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Write header
	headerRow := "|"
	dividerRow := "|"
	for i, header := range table.Headers {
		formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
		headerRow += fmt.Sprintf(formatter, header)
		dividerRow += fmt.Sprintf(" %s |", strings.Repeat("-", colWidths[i]))
	}
	headerRow += "\n"
	dividerRow += "\n"
	file.WriteString(headerRow)
	file.WriteString(dividerRow)

	// Write rows
	for _, row := range table.Rows {
		rowText := "|"
		for i, cell := range row {
			formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
			rowText += fmt.Sprintf(formatter, cell)
		}
		rowText += "\n"
		file.WriteString(rowText)
	}
	file.WriteString("\n\n\n")
	message.Success("Markdown table written to %s", fullpath)
	return nil
}

func (fp *MarkdownFileProvider) DefaultFileName(prefix string) string {
	return DefaultFileName(prefix, "md")
}
