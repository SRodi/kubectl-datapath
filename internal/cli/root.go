package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/SRodi/kubectl-datapath/internal/agent"
	"github.com/SRodi/kubectl-datapath/internal/version"
)

func NewRootCommand() *cobra.Command {
	command := &cobra.Command{
		Use:           "datapath",
		Short:         "Trace the Kubernetes network datapath",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	usageTemplate := command.UsageTemplate()
	usageTemplate = strings.ReplaceAll(usageTemplate, "{{.UseLine}}", "kubectl {{.UseLine}}")
	usageTemplate = strings.ReplaceAll(usageTemplate, "{{.CommandPath}}", "kubectl {{.CommandPath}}")
	command.SetUsageTemplate(usageTemplate)
	command.InitDefaultHelpFlag()
	command.Flags().Lookup("help").Usage = "help for kubectl datapath"
	command.AddCommand(newCompatibilityCommand(), newVersionCommand(), newReplayCommand(), newTraceCommand(), newAgentCommand())
	return command
}

func newCompatibilityCommand() *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:   "compatibility",
		Short: "Report this machine's local capture environment, not cluster-node compatibility",
		RunE: func(command *cobra.Command, _ []string) error {
			result := agent.ProbeLocal()
			if output == "json" {
				return json.NewEncoder(command.OutOrStdout()).Encode(result)
			}
			fmt.Fprintln(command.OutOrStdout(), "Local process environment only; trace agents run on Kubernetes nodes.")
			fmt.Fprintf(command.OutOrStdout(), "Kernel: %s\n", result.Kernel)
			for _, capability := range result.Capabilities {
				state := "unavailable"
				if capability.Available {
					state = "available"
				}
				fmt.Fprintf(command.OutOrStdout(), "  %-18s %-11s %s\n", capability.Name, state, capability.Detail)
			}
			return nil
		},
	}
	command.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	return command
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client and default agent image versions",
		Run: func(command *cobra.Command, _ []string) {
			fmt.Fprintf(command.OutOrStdout(), "kubectl-datapath %s\nagent image %s\n",
				version.Version, version.AgentImage())
		},
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func openInput(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return file, nil
}
