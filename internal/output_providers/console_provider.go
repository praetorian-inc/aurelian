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

// Write writes the `data` field of the result
// to the console.
func (cp *ConsoleProvider) Write(result modules.Result) error {
	helpers.PrintMessage(result.StringData())
	return nil
}
