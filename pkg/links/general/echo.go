package general

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
)

type Echo[T any] struct {
	*chain.Base
}

func NewEcho[T any](configs ...cfg.Config) chain.Link {
	e := &Echo[T]{}
	e.Base = chain.NewBase(e, configs...)
	return e
}

func (e *Echo[T]) Process(input T) error {
	// Pass it through
	e.Send(input)
	return nil
}
