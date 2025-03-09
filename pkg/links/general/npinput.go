package general

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/links"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
)

func NewToNPInput(configs ...cfg.Config) chain.Link {
	return links.FromTransformerSlice(func(input jtypes.CanNPInput) ([]jtypes.NPInput, error) {
		return input.ToNPInputs()
	})
}
