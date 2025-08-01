package links

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
)

func TestCCBasic(t *testing.T) {
	c := chain.NewChain(
		cloudcontrol.NewAWSCloudControl(),
	).WithOutputters(
		output.NewConsoleOutputter(),
		output.NewJSONOutputter(),
	).WithConfigs(
		cfg.WithArg("regions", []string{"all"}),
		cfg.WithArg("profile", "default"),
		cfg.WithArg("jsonoutfile", "cloudcontrol2.json"),
	).WithStrictness(
		chain.Strict)

	t.Logf("Params: %v", c.Params())

	c.Send("AWS::Lambda::Function")
	c.Send("AWS::CloudFormation::Stack")
	c.Close()
	c.Wait()
	if c.Error() != nil {
		fmt.Println(c.Error())
	}
}
