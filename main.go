package main

import (
	"os"
	"runtime/debug"

	"github.com/praetorian-inc/diocletian/cmd"
)

func main() {
	debug.SetMaxThreads(20000)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
