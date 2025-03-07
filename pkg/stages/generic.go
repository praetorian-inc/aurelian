// The stages package provides pipeline components for processing cloud resources.
// Stages are composable building blocks that implement Go's pipeline pattern
// through channel-based communication.
//
// A stage is a function that processes input from an input channel and writes results
// to an output channel. Stages can be chained together using ChainStages to create
// reusable processing pipelines.
//
// Each stage implements this core type signature:
//
//	type Stage[In any, Out any] func(ctx context.Context, opts []*types.Option, in <-chan In) <-chan Out
//
// Common stage patterns include:
//   - Resource enumeration
//   - Filtering and transformation
//   - Aggregation of results
//   - Output formatting
//
// Example usage:
//
//	// Chain stages to list AWS resources and aggregate results
//	pipeline, err := stages.ChainStages[string, []types.EnrichedResourceDescription](
//	    stages.CloudControlListResources,
//	    stages.AggregateOutput[types.EnrichedResourceDescription],
//	)
//
// Stages are designed to be:
//   - Composable - can be chained together in flexible ways
//   - Type-safe - using Go generics to ensure type compatibility
//   - Context-aware - supporting cancellation and deadlines
//   - Reusable - implementing common processing patterns
//
// See individual stage documentation for details on specific implementations.
package stages

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ollama/ollama/api"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// GenerateOllamaResponse generates responses for given prompts using the Ollama API.
// It takes a context, a slice of options, and an input channel of strings, and returns an output channel of strings.
//
// The function initializes an API client from the environment and starts a goroutine to process prompts from the input channel.
// For each prompt, it logs the prompt, constructs a generate request, and sends it to the API client.
// The responses are logged and sent to the output channel. If an error occurs, it is logged and the processing stops.
func GenerateOllamaResponse(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "GenerateOllamaResponse")
	out := make(chan string)
	client, err := api.ClientFromEnvironment()
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	go func() {
		defer close(out)
		for prompt := range in {
			logger.Info("Generating response for prompt: " + prompt)
			model := options.GetOptionByName(options.ModelOpt.Name, opts).Value
			req := &api.GenerateRequest{
				Model:  model,
				Prompt: prompt,
				Stream: new(bool),
			}

			respFunc := func(resp api.GenerateResponse) error {
				logger.Info(resp.Response)
				out <- resp.Response
				return nil
			}

			err = client.Generate(ctx, req, respFunc)
			if err != nil {
				logger.Error(err.Error())
				return
			}
		}
	}()

	return out

}

// ToJsonBytes converts input data from a channel to JSON-encoded byte slices and sends them to an output channel.
// It logs any errors encountered during the JSON marshaling process.
func ToJsonBytes[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan []byte {
	logger := logs.NewStageLogger(ctx, opts, "ToJsonBytes")
	out := make(chan []byte)
	go func() {
		defer close(out)
		for data := range in {
			jsonData, err := json.Marshal(data)
			if err != nil {
				logger.Error(err.Error())
				return
			}
			out <- jsonData
		}
	}()
	return out
}

// ToJson converts a channel of any type to a channel of JSON-encoded byte slices.
// It logs any errors encountered during the JSON marshaling process.
func ToJson[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan []byte {
	logger := logs.NewStageLogger(ctx, opts, "ToJson")
	out := make(chan []byte)
	go func() {
		defer close(out)
		for resource := range in {
			res, err := json.Marshal(resource)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			out <- res
		}
	}()
	return out
}

// JqFilter applies a JQ filter to the input data and returns the filtered result.
// It takes a context and a JQ filter string as parameters and returns a Stage function
// that processes a channel of byte slices.
//
// The Stage function logs any errors encountered during the filtering process and continues processing
// the remaining data.
func JqFilter(ctx context.Context, filter string) Stage[[]byte, []byte] {
	logger := logs.NewStageLogger(ctx, []*types.Option{}, "JqFilter")
	return func(ctx context.Context, opts []*types.Option, in <-chan []byte) <-chan []byte {
		out := make(chan []byte)
		go func() {
			defer close(out)
			for data := range in {
				filtered, err := utils.PerformJqQuery(data, filter)
				if err != nil {
					logger.Error(err.Error())
					continue
				}

				if len(filtered) > 0 {
					out <- filtered
				}
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
			switch v := any(data).(type) {
			case []byte:
				if utils.IsASCII(v) {
					out <- string(v)
				} else {
					out <- fmt.Sprintf("%v", data)
				}
			default:
				out <- fmt.Sprintf("%v", data)
			}
		}
	}()
	return out
}

// UnmarshalOutput unmarshals JSON data from a channel of strings to a channel of maps.
func UnmarshalOutput(ctx context.Context, opts []*types.Option, in <-chan string) <-chan map[string]interface{} {
	logger := logs.NewStageLogger(ctx, opts, "UnmarshalOutput")
	out := make(chan map[string]interface{})
	go func() {
		defer close(out)
		for data := range in {
			var jsonObj map[string]interface{}
			err := json.Unmarshal([]byte(data), &jsonObj)
			if err != nil {
				logger.Debug("Failed to unmarshal JSON data: " + base64.StdEncoding.EncodeToString([]byte(data)))
				logger.Error(err.Error())
				continue
			}
			out <- jsonObj
		}
	}()
	return out
}

// AggregateOutput aggregates all items from an input channel into a single slice.
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

// GetFilesOfType reads files from a directory and filters them based on the file extension.
func GetFilesOfType(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "GetFilesOfType")
	out := make(chan string)
	go func() {
		defer close(out)
		inputLoc := options.GetOptionByName(options.DirPathOpt.Name, opts).Value
		for extension := range in {
			inputFiles, err := os.ReadDir(inputLoc)
			if err != nil {
				logger.Error(err.Error())
				return
			}
			for _, file := range inputFiles {
				if strings.HasSuffix(file.Name(), extension) {
					out <- filepath.Join(inputLoc, file.Name())
				}
			}
		}
	}()
	return out
}

// FileGenerator reads lines from files provided via an input channel and sends them to an output channel.
// Each file is read line by line, and each line is sent to the output channel. After reading all lines,
// the file name is sent to the output channel.
func FileGenerator(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "FileGenerator")
	out := make(chan string)
	go func() {
		defer close(out)
		for file := range in {
			f, err := os.Open(file)
			if err != nil {
				logger.Error(err.Error())
				return
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				out <- scanner.Text()
			}

			if err := scanner.Err(); err != nil {
				logger.Error(err.Error())
			}
		}
	}()
	return out
}

// UnqueItemsStage ensures that only unique items are sent to the output channel.
// It uses a map to keep track of items that have already been seen and sends only unseen items to the output channel.
func UnqueItemsStage[Item comparable](ctx context.Context, opts []*types.Option, in <-chan Item) <-chan Item {
	out := make(chan Item)
	go func() {
		defer close(out)
		seen := make(map[Item]bool)
		for item := range in {
			if _, ok := seen[item]; !ok {
				seen[item] = true
				out <- item
			}
		}
	}()
	return out
}

// SplitByComma splits a comma-separated string of resource types into a channel of strings.
func SplitByComma(types string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for _, t := range strings.Split(types, ",") {
			out <- t
		}
	}()
	return out
}
