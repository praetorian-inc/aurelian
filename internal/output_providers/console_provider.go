package outputproviders

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

type ConsoleProvider struct {
	types.OutputProvider
}

func NewConsoleProvider(options []*types.Option) types.OutputProvider {
	return &ConsoleProvider{}
}

// Write writes the `data` field of the result
// to the console.
func (cp *ConsoleProvider) Write(result types.Result) error {
	//helpers.PrintResult(result)
	res := result.Data.(string)
	if res != "" {
		fmt.Println(res)
	}
	return nil
}
