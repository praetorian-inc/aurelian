package outputproviders

import (
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type ConsoleProvider struct {
	modules.OutputProvider
}

func NewConsoleProvider(options []*options.Option) modules.OutputProvider {
	return &ConsoleProvider{}
}

func (cp *ConsoleProvider) Write(result modules.Result) error {
	helpers.PrintMessage(result.String())
	return nil
}
