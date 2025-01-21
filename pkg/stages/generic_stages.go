package stages

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			model := types.GetOptionByName(options.ModelOpt.Name, opts).Value
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

func UnmarshalOutput(ctx context.Context, opts []*types.Option, in <-chan string) <-chan map[string]interface{} {
	logger := logs.NewStageLogger(ctx, opts, "UnmarshalOutput")
	out := make(chan map[string]interface{})
	go func() {
		defer close(out)
		for data := range in {
			var jsonObj map[string]interface{}
			err := json.Unmarshal([]byte(data), &jsonObj)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			out <- jsonObj
		}
	}()
	return out
}

// func ReplaceBackslashes(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
// 	out := make(chan string)
// 	go func() {
// 		defer close(out)
// 		for data := range in {
// 			newString := strings.ReplaceAll(data, "\\\"", "\"")
// 			newString = strings.ReplaceAll(newString, "\\", "")
// 			fmt.Println(newString)
// 			out <- newString
// 		}
// 	}()
// 	return out
// }

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

func GetFilesOfType(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "GetFilesOfType")
	out := make(chan string)
	go func() {
		defer close(out)
		inputLoc := types.GetOptionByName(options.DirPathOpt.Name, opts).Value
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
//
// Parameters:
//
//	ctx - context for managing the lifecycle of the goroutine.
//	opts - a slice of options (currently unused).
//	in - a channel that provides file paths to be read.
//
// Returns:
//
//	A channel that emits lines read from the files and the file name after all lines are read.
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
