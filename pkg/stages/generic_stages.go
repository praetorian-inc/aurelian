package stages

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ollama/ollama/api"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
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
func GenerateOllamaResponse(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
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
			model := types.GetOptionByName(options.ModelOpt.Name, opts).Value
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

func ToJsonBytes[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		for data := range in {
			jsonData, err := json.Marshal(data)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				return
			}
			out <- jsonData
		}
	}()
	return out
}

func JqFilter(filter string) Stage[[]byte, []byte] {
	return func(ctx context.Context, opts []*types.Option, in <-chan []byte) <-chan []byte {
		out := make(chan []byte)
		go func() {
			defer close(out)
			for data := range in {
				filtered, err := utils.PerformJqQuery(data, filter)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}
				out <- filtered
			}
		}()
		return out
	}
}

// ToString converts any input channel of type In to an output channel of strings.
// It reads from the input channel, formats each item as a string using fmt.Sprintf,
// and sends the formatted string to the output channel. The output channel is closed
// once all input has been processed.
func ToString[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for data := range in {
			out <- fmt.Sprintf("%v", data)
		}
	}()
	return out
}

func AggregateOutput[In any, Out []In](ctx context.Context, opts []*types.Option, in <-chan In) <-chan Out {
	out := make(chan Out)
	var items Out

	go func() {
		defer close(out)
		for data := range in {
			items = append(items, data)
		}

		out <- items
	}()
	return out
}
