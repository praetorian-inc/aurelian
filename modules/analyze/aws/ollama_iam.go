package analyze

import (
	"os"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsOllamaIam struct {
	modules.BaseModule
}

var AwsOllamaIamMetadata = modules.Metadata{
	Id:          "ollama-iam",
	Name:        "Ollama IAM",
	Description: "This module analyzes IAM policy information for issues. It appends the policy to the prompt and sends it to the Ollama API for analysis.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

var AwsOllamaIamOptions = []*types.Option{
	&o.PathOpt,
	types.SetRequired(o.UrlOpt, false),
	types.SetRequired(o.PromptOpt, false),
	types.SetRequired(o.ModelOpt, false),
}

var AwsOllamaIamOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

func NewAwsOllamaIam(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {

	urlOpt := types.GetOptionByName(o.UrlOpt.Name, opts)
	if urlOpt.Value == "" {
		urlOpt.Value = "http://localhost:11434/api"
	}

	// Get the default base prompt
	promptOpt := types.GetOptionByName(o.PromptOpt.Name, opts)
	if promptOpt.Value == "" {
		promptOpt.Value = "Print the arn of the IAM Policy below. Then analyze the AWS Policy for security weaknesses. Please expand all actions with a wildcard to understand the risk they actions may pose. Print a list of security weaknesses. Respond None if there are no weaknesses. Finally rate the risk of the policy."
	}

	polBytes, err := os.ReadFile(types.GetOptionByName(o.PathOpt.Name, opts).Value)
	if err != nil {
		return nil, nil, err
	}

	policy := string(polBytes)
	prompt := promptOpt.Value + "\n" + policy

	pipeline, err := stages.ChainStages[string, string](
		stages.GenerateOllamaResponse,
	)
	if err != nil {
		return nil, nil, err
	}

	return stages.Generator([]string{prompt}), pipeline, nil

}
