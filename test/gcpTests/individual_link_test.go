package gcpTests

import (
	"testing"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
)

func TestGcpFunctionInfoLink(t *testing.T) {
	c := chain.NewChain(
		applications.NewGcpFunctionInfoLink(),
	).WithOutputters(
		output.NewConsoleOutputter(),
		output.NewJSONOutputter(),
	).WithConfigs(
		cfg.WithArg("project", "praetorian-inc"),
		cfg.WithArg("region", "us-central1"),
	).WithStrictness(
		chain.Strict,
	)
	c.Send("gcp-function-info-link")
	c.Close()
	c.Wait()
}
