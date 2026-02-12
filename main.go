package main

import (
	"os"
	"runtime/debug"

	"github.com/praetorian-inc/aurelian/cmd"

	// Import all modules to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func main() {
	debug.SetMaxThreads(20000)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
