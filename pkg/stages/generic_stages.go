package stages

import (
	"context"

	"github.com/ollama/ollama/api"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
)

// GenerateOllamaResponse generates responses for given prompts using the Ollama API.
// It takes a context, a slice of options, and an input channel of strings, and returns an output channel of strings.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - opts: A slice of options to configure the API client and request.
//   - in: An input channel of strings containing prompts for which responses are to be generated.
//
// Returns:
//   - An output channel of strings containing the generated responses.
//
// The function initializes an API client from the environment and starts a goroutine to process prompts from the input channel.
// For each prompt, it logs the prompt, constructs a generate request, and sends it to the API client.
// The responses are logged and sent to the output channel. If an error occurs, it is logged and the processing stops.
func GenerateOllamaResponse(ctx context.Context, opts []*options.Option, in <-chan string) <-chan string {
	out := make(chan string)
	client, err := api.ClientFromEnvironment()
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	go func() {
		defer close(out)
		for prompt := range in {
			logs.ConsoleLogger().Info("Generating response for prompt: " + prompt)
			model := options.GetOptionByName(options.ModelOpt.Name, opts).Value
			req := &api.GenerateRequest{
				Model:  model,
				Prompt: prompt,
				Stream: new(bool),
			}

			respFunc := func(resp api.GenerateResponse) error {
				logs.ConsoleLogger().Info(resp.Response)
				out <- resp.Response
				return nil
			}

			err = client.Generate(ctx, req, respFunc)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				return
			}
		}
	}()

	return out

}
