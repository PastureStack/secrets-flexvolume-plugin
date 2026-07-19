package main

import (
	"os"

	"github.com/PastureStack/secrets-flexvolume-plugin/internal/cli"
	"github.com/PastureStack/secrets-flexvolume-plugin/internal/driver"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		os.Exit(driver.RunServe(args[1:], os.Stdout, os.Stderr, version))
	}
	os.Exit(cli.Run(args, os.Stdin, os.Stdout, os.Stderr))
}
