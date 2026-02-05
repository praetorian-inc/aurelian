package main

import (
	"os"
	"runtime/debug"

	"github.com/praetorian-inc/aurelian/cmd"

	// Import all modules to trigger init() registration
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/analyze"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/secrets"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/saas/recon"
)

func main() {
	debug.SetMaxThreads(20000)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
