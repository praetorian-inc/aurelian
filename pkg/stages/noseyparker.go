package stages

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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

	// Create mutex to protect encoder writes
	var encoderMu sync.Mutex

	go func() {
		// Create pipe for stdin
		pipeReader, pipeWriter := io.Pipe()

		// Create pipe for stderr
		stderrReader, stderrWriter := io.Pipe()

		// Create channel to track current input being processed
		currentInput := make(chan types.NpInput, 1)

		// Create a single encoder instance that will be protected by the mutex
		encoder := json.NewEncoder(pipeWriter)

		// Function to safely write to the encoder
		writeInput := func(data types.NpInput) error {
			encoderMu.Lock()
			defer encoderMu.Unlock()
			return encoder.Encode(data)
		}

		// Start goroutine to handle stderr
		go func() {
			scanner := bufio.NewScanner(stderrReader)
			for scanner.Scan() {
				// Try to get current input context
				var input types.NpInput
				select {
				case input = <-currentInput:
					currentInput <- input // Put it back for other error messages
				default:
					// No input context available
				}

				if input.Provenance.ResourceID != "" {
					// Log with input context
					logger.Error(scanner.Text(),
						slog.String("resource_id", input.Provenance.ResourceID),
						slog.String("resource_type", input.Provenance.ResourceType),
						slog.String("platform", input.Provenance.Platform),
						slog.String("region", input.Provenance.Region),
						slog.String("account_id", input.Provenance.AccountID),
					)
				} else {
					// Log without context
					logger.Error(scanner.Text())
				}
			}
			if err := scanner.Err(); err != nil {
				logger.Error("Error reading stderr: " + err.Error())
			}
		}()

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
			cmd.Stderr = stderrWriter

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

		// Single input processor goroutine
		go func() {
			defer func() {
				pipeWriter.Close()
				stderrWriter.Close()
			}()

			for data := range in {
				select {
				case <-ctx.Done():
					return
				default:
					switch v := any(data).(type) {
					case types.NpInput:
						// Update current input context
						select {
						case <-currentInput: // Clear old input if present
						default:
						}
						currentInput <- data

						if slog.Default().Enabled(ctx, slog.LevelDebug) {
							dataJson, err := json.Marshal(data)
							if err != nil {
								logger.Error(fmt.Sprintf("failed to marshal data for debug: %v", err))
							} else {
								debugFile, err := os.OpenFile("np-debug.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
								if err != nil {
									logger.Error(fmt.Sprintf("failed to open debug file: %v", err))
								} else {
									defer debugFile.Close()
									if _, err := debugFile.WriteString(string(dataJson) + "\n"); err != nil {
										logger.Error(fmt.Sprintf("failed to write to debug file: %v", err))
									}
								}
							}
						}

						if err := writeInput(data); err != nil {
							logger.Error(fmt.Sprintf("failed to encode input: %v", err),
								slog.String("resource_id", data.Provenance.ResourceID),
								slog.String("resource_type", data.Provenance.ResourceType),
								slog.String("platform", data.Provenance.Platform),
								slog.String("region", data.Provenance.Region),
								slog.String("account_id", data.Provenance.AccountID),
							)
							continue
						}
						logger.Debug(fmt.Sprintf("sent data to noseyparker: %v", data))
					default:
						logger.Error(fmt.Sprintf("unsupported input type: %T", v))
						continue
					}
				}
			}
		}()
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
				logger.Error("failed to marshal properties to json", slog.String("error", err.Error()))
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
