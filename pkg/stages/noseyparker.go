package stages

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// NoseyParkerEnumeratorStage processes data and streams it to noseyparker using a named pipe
func NoseyParkerEnumeratorStage(ctx context.Context, opts []*types.Option, in <-chan types.NpInput) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "NoseyParkerEnumeratorStage")
	out := make(chan string)
	stdOut := make(chan string)

	go func() {
		// Create pipe for stdin
		pipeReader, pipeWriter := io.Pipe()

		// Start noseyparker in goroutine
		go func() {
			defer close(stdOut)

			datastore, err := filepath.Abs(filepath.Join(options.GetOptionByName(options.OutputOpt.Name, opts).Value, options.GetOptionByName(options.NoseyParkerOutputOpt.Name, opts).Value))
			if err != nil {
				logger.Error(fmt.Sprintf("failed to get absolute path for datastore: %v", err))
				return
			}

			message.Info(fmt.Sprintf("Writing Nosey Parker Results to %s", datastore))

			npPath, err := helpers.FindBinary(options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to find noseyparker: %v", err))
				return
			}
			logger.Debug(fmt.Sprintf("noseyparker path: %v", npPath))

			npOpts := []string{"scan", "--datastore", datastore, "--progress", "never", "--enumerator", "/dev/stdin"}
			cliOpts := options.GetOptionByName(options.NoseyParkerArgsOpt.Name, opts).Value
			logger.Debug(fmt.Sprintf("noseyparker cli options: %v", cliOpts))
			if cliOpts != "" {
				parsed := strings.Split(cliOpts, " ")
				logger.Debug(fmt.Sprintf("parsed options: %v", parsed))
				npOpts = append(npOpts, parsed...)
			}

			logger.Debug(fmt.Sprintf("noseyparker merged options: %v", npOpts))
			cmd := exec.CommandContext(ctx, npPath, npOpts...)
			logger.Debug(fmt.Sprintf("noseyparker command: %v", cmd.String()))
			cmd.Stdin = pipeReader
			cmd.Stderr = os.Stderr

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				logger.Error(fmt.Sprintf("failed to create stdout pipe: %v", err))
				return
			}

			if err := cmd.Start(); err != nil {
				logger.Error(fmt.Sprintf("failed to start noseyparker: %v", err))
				return
			}

			// Process stdout
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					return
				case stdOut <- scanner.Text():
					logger.Debug(scanner.Text())
				}
			}

			if err := cmd.Wait(); err != nil && ctx.Err() == nil {
				logger.Error(fmt.Sprintf("noseyparker command failed: %v", err))
			}
		}()

		// Write to stdin pipe
		encoder := json.NewEncoder(pipeWriter)
		for data := range in {
			select {
			case <-ctx.Done():
				pipeWriter.Close()
				return
			default:
				switch v := any(data).(type) {
				case types.NpInput:
					if err := encoder.Encode(data); err != nil {
						logger.Error(fmt.Sprintf("failed to encode input: %v", err))
						continue
					}
					logger.Debug(fmt.Sprintf("sent data to noseyparker: %v", data))
				default:
					logger.Error(fmt.Sprintf("unsupported input type: %T", v))
					continue
				}
			}
		}
		pipeWriter.Close()
	}()

	// Process noseyparker output
	go func() {
		defer close(out)
		var outputBuilder strings.Builder
		for result := range stdOut {
			outputBuilder.WriteString(result)
			outputBuilder.WriteString("\n")
		}
		out <- outputBuilder.String()
	}()

	return out
}

func EnrichedResourceDescriptionToNpInput(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "EnrichedResourceDescriptionToNpInput")
	out := make(chan types.NpInput)
	go func() {
		defer close(out)
		for data := range in {
			metadata := ctx.Value("metadata").(modules.Metadata)
			propsJson, err := json.Marshal(data.Properties)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			out <- types.NpInput{
				ContentBase64: base64.StdEncoding.EncodeToString(propsJson),
				Provenance: types.NpProvenance{
					Platform:     string(metadata.Platform),
					ResourceType: data.TypeName,
					ResourceID:   data.Arn.String(),
					Region:       data.Region,
					AccountID:    data.AccountId,
				},
			}
		}
	}()
	return out
}
