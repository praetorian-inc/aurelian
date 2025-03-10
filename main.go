package main

import (
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/praetorian-inc/nebula/cmd"
)

func main() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	debug.SetMaxThreads(20000)
	cmd.Execute()
}
