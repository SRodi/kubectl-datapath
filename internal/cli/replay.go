package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/SRodi/kubectl-datapath/internal/replay"
	"github.com/SRodi/kubectl-datapath/internal/tui"
)

func newReplayCommand() *cobra.Command {
	var noTUI bool
	command := &cobra.Command{
		Use:   "replay <events.ndjson>",
		Short: "Replay a saved observation stream",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			file, err := openInput(args[0])
			if err != nil {
				return err
			}
			defer file.Close()

			ctx, cancel := signalContext()
			defer cancel()
			observations, errors := replay.Stream(ctx, file)
			if noTUI {
				encoder := json.NewEncoder(command.OutOrStdout())
				for observation := range observations {
					if err := encoder.Encode(observation); err != nil {
						return err
					}
				}
				if err := <-errors; err != nil {
					return err
				}
				return nil
			}
			if err := tui.Run(ctx, "replay · "+args[0], observations, errors, os.Stdin, command.OutOrStdout()); err != nil {
				return fmt.Errorf("run TUI: %w", err)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&noTUI, "no-tui", false, "write normalized NDJSON instead of opening the TUI")
	return command
}
