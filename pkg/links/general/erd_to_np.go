package general

import (
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type ErdToNPInput struct {
	*chain.Base
}

func NewErdToNPInput(configs ...cfg.Config) chain.Link {
	r := &ErdToNPInput{}
	r.Base = chain.NewBase(r, configs...)
	return r
}

func (r *ErdToNPInput) Process(data *types.EnrichedResourceDescription) error {
	npInput, err := data.ToNPInput()
	if err != nil {
		slog.Error("failed to convert resource to NP input", "error", err)
		return err
	}

	r.Send(npInput)
	return nil
}
