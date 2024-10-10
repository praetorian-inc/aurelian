package stages

import (
	"context"

	"github.com/ollama/ollama/api"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
)

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
