package main

import (
	"fmt"
	"os"

	"github.com/SRodi/kubectl-datapath/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
