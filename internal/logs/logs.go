package logs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/smithy-go/logging"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var (
	logLevel string
)

const (
	LevelNone = slog.Level(12)
)

// Currently used to write the AWS API calls to a log file
func AwsCliLogger() logging.Logger {
	return logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
		LOG_FILE := "nebula.log"

		opts := &slog.HandlerOptions{
			AddSource: true,
			Level:     getLevelFromString(logLevel),
		}

		var f *os.File
		var err error

		if getLevelFromString(logLevel) != LevelNone {
			f, err = os.OpenFile(LOG_FILE, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				panic(err)
			}
			defer f.Close()
		}

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
	case "none":
		return LevelNone
	default:
		return LevelNone
	}
}

func NewLogger() *slog.Logger {
	fmt.Printf("log level: %s\n", logLevel)
	w := os.Stderr
	handler := tint.NewHandler(w,
		&tint.Options{
			Level:   getLevelFromString(logLevel),
			NoColor: !isatty.IsTerminal(w.Fd()),
		},
	)
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
