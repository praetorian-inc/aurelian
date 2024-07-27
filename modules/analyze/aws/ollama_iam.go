package analyze

import (
	"context"
	"os"

	api "github.com/ollama/ollama/api"
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

var AwsOllamaIamRequiredOptions = []*o.Option{
	&o.PathOpt,
	// TODO we need a way to have non-required options
	//&o.UrlOpt,
	//&o.PromptOpt,
}

var AwsOllamaIamOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

func NewAwsOllamaIam(options []*o.Option, run modules.Run) (modules.Module, error) {
	var m AwsOllamaIam
	m.SetMetdata(AwsOllamaIamMetadata)
	m.Run = run

	// TODO we need a way to have non-required options
	urlOpt := o.UrlOpt
	urlOpt.Value = "http://localhost:11434/api"
	options = append(options, &urlOpt)

	promptOpt := o.PromptOpt
	promptOpt.Value = "In ithe AWS Policy below, what security weaknesses are present? Please list all weaknesses, be thorough. Respond None if there are no weaknesses. Finally rate the risk of the policy."
	options = append(options, &promptOpt)

	m.Options = options
	m.ConfigureOutputProviders(AwsOllamaIamOutputProviders)

	return &m, nil
}

func (m *AwsOllamaIam) Invoke() error {
	client, err := api.ClientFromEnvironment()
	if err != nil {
		return err
	}

	prompt := m.GetOptionByName(o.PromptOpt.Name).Value
	polBytes, err := os.ReadFile(m.GetOptionByName(o.PathOpt.Name).Value)
	if err != nil {
		return err
	}

	policy := string(polBytes)
	prompt = prompt + "\n" + policy

	req := &api.GenerateRequest{
		Model:  "llama3",
		Prompt: prompt,
		Stream: new(bool),
	}

	respFunc := func(resp api.GenerateResponse) error {
		m.Run.Data <- m.MakeResult(resp.Response)
		close(m.Run.Data)
		return nil
	}
	ctx := context.Background()
	err = client.Generate(ctx, req, respFunc)
	if err != nil {
		return err
	}

	return nil
}

/*
func (m *AwsOllamaIam) generateResponse(res *api.GenerateResponse) api.GenerateResponseFunc {
	fmt.Println(res.Response)
	m.Run.Data <- m.MakeResult(res)
	return nil
}
*/
