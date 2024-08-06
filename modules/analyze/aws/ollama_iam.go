package analyze

import (
	"os"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
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

var AwsOllamaIamOptions = []*o.Option{
	&o.PathOpt,
	o.SetRequired(&o.UrlOpt, false),
	o.SetRequired(&o.PromptOpt, false),
	o.SetRequired(&o.ModelOpt, false),
}

var AwsOllamaIamOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

func NewAwsOllamaIam(options []*o.Option, run modules.Run) (modules.Module, error) {
	var m AwsOllamaIam
	m.SetMetdata(AwsOllamaIamMetadata)
	m.Run = run

	urlOpt := o.GetOptionByName(o.UrlOpt.Name, options)
	if urlOpt.Value == "" {
		urlOpt.Value = "http://localhost:11434/api"
	}

	promptOpt := o.GetOptionByName(o.PromptOpt.Name, options)
	if promptOpt.Value == "" {
		promptOpt.Value = "Print the arn of the IAM Policy below. Then analyze the AWS Policy for security weaknesses. Please expand all actions with a wildcard to understand the risk they actions may pose. Print a list of security weaknesses. Respond None if there are no weaknesses. Finally rate the risk of the policy."
	}

	m.Options = options
	m.ConfigureOutputProviders(AwsOllamaIamOutputProviders)

	return &m, nil
}

func (m *AwsOllamaIam) Invoke() error {

	prompt := m.GetOptionByName(o.PromptOpt.Name).Value
	polBytes, err := os.ReadFile(m.GetOptionByName(o.PathOpt.Name).Value)
	if err != nil {
		return err
	}

	policy := string(polBytes)
	prompt = prompt + "\n" + policy

	err = m.GenerateOllamaResponse(prompt)
	if err != nil {
		return err
	}

	close(m.Run.Data)
	return nil
}
