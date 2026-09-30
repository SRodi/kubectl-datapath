package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootHelpUsesKubectlPluginCommand(t *testing.T) {
	root := NewRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	if !strings.Contains(help, "Usage:\n  kubectl datapath [command]") {
		t.Fatalf("plugin usage missing:\n%s", help)
	}
	if strings.Contains(help, "kubectl-datapath") {
		t.Fatalf("binary name leaked into plugin help:\n%s", help)
	}

	output.Reset()
	root.SetArgs([]string{"trace", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if help = output.String(); !strings.Contains(help, "Usage:\n  kubectl datapath trace [command]") {
		t.Fatalf("subcommand usage missing:\n%s", help)
	}
}

func TestRootExposesOneTraceWorkflow(t *testing.T) {
	root := NewRootCommand()
	if command, _, err := root.Find([]string{"observe"}); err == nil && command.Name() == "observe" {
		t.Fatal("legacy observe command is still exposed")
	}
	traceCommand, _, err := root.Find([]string{"trace", "pod"})
	if err != nil {
		t.Fatal(err)
	}
	if traceCommand.Name() != "pod" {
		t.Fatalf("command = %q", traceCommand.Name())
	}
	to := traceCommand.Flag("to")
	if to == nil || to.DefValue != "" {
		t.Fatalf("--to flag = %#v", to)
	}
	if annotation := to.Annotations[cobra.BashCompOneRequiredFlag]; len(annotation) == 0 {
		t.Fatal("--to is not required")
	}
}
