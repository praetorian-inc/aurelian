package logs

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/smithy-go/logging"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var (
	logLevel string
)

// Currently used to write the AWS API calls to a log file
func AwsCliLogger() logging.Logger {
	return logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
		LOG_FILE := "nebula.log"

		opts := &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}

		f, err := os.OpenFile(LOG_FILE, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		handler := slog.NewJSONHandler(f, opts)
		logger := slog.New(handler)

		// TODO: The key for the request is `!BADKEY`, need to fix
		switch classification {
		case logging.Debug:
			logger.Debug(format, v...)
		case logging.Warn:
			logger.Warn(format, v...)
		default:
			logger.Debug(format, v...)
		}

	})
}

func getLevelFromString(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func NewLogger() *slog.Logger {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLevelFromString(logLevel),
	})
	logger := slog.New(handler)

	return logger
}

func NewModuleLogger(ctx context.Context, opts []*types.Option) *slog.Logger {
	logger := NewLogger()
	metadata := ctx.Value("metadata").(modules.Metadata)
	child := logger.WithGroup("module").With("platform", metadata.Platform).With("id", metadata.Id)

	return child
}

func NewStageLogger(ctx context.Context, opts []*types.Option, stage string) *slog.Logger {
	logger := NewModuleLogger(ctx, opts)
	return logger.With("stage", stage)
}

func SetLogLevel(level string) {
	logLevel = level
}

func ConfigureDefaults(level string) {
	SetLogLevel(level)
	logger := NewLogger()
	slog.SetDefault(logger)
}
