package outputters

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// MarkdownTableConsoleOutputter outputs MarkdownTable types to console
type MarkdownTableConsoleOutputter struct {
	cfg plugin.Config
}

// NewMarkdownTableConsoleOutputter creates a new console outputter for MarkdownTable types
func NewMarkdownTableConsoleOutputter() *MarkdownTableConsoleOutputter {
	return &MarkdownTableConsoleOutputter{}
}

func (o *MarkdownTableConsoleOutputter) Initialize(cfg plugin.Config) error {
	o.cfg = cfg
	return nil
}

func (o *MarkdownTableConsoleOutputter) Output(val any) error {
	if table, ok := val.(types.MarkdownTable); ok {
		fmt.Print(table.ToString())
		return nil
	}
	return nil
}

func (o *MarkdownTableConsoleOutputter) Complete() error {
	return nil
}