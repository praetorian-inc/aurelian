package outputters

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// MarkdownTableConsoleOutputter outputs MarkdownTable types to console
type MarkdownTableConsoleOutputter struct {
	*chain.BaseOutputter
}

// NewMarkdownTableConsoleOutputter creates a new console outputter for MarkdownTable types
func NewMarkdownTableConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &MarkdownTableConsoleOutputter{}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

func (o *MarkdownTableConsoleOutputter) Output(val any) error {
	if table, ok := val.(types.MarkdownTable); ok {
		fmt.Print(table.ToString())
		return nil
	}
	return nil
}

func (o *MarkdownTableConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}