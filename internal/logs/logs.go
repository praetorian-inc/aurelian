package logs

import (
	"log/slog"
	"os"
	"time"

	"github.com/aws/smithy-go/logging"
	"github.com/lmittmann/tint"
)

func Logger() logging.Logger {
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

func ConsoleLogger() *slog.Logger {

	/*
		config := zap.NewProductionEncoderConfig()
		config.EncodeLevel = zapcore.CapitalColorLevelEncoder
		core := zapcore.NewCore(
			zapcore.NewConsoleEncoder(config),
			zapcore.AddSync(os.Stdout),
			zap.DebugLevel,
		)
		logger := zap.New(core)
		defer logger.Sync()
		return logger
	*/
	w := os.Stderr

	// create a new logger
	logger := slog.New(tint.NewHandler(w, nil))

	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
		}),
	))
	return logger
}
