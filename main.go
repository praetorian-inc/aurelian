package main

import (
	"runtime/debug"

	"github.com/praetorian-inc/nebula/cmd"
)

func main() {
	debug.SetMaxThreads(20000)
	cmd.Execute()
}
