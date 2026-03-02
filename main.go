package main

import (
	"os"
	"runtime/debug"

	"github.com/praetorian-inc/aurelian/cmd"

	// Import all modules to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"

	// Import analyze modules to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/analyze"

	// Import enrichers to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"

	// Import Azure modules to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon"
)

func main() {
	debug.SetMaxThreads(20000)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
