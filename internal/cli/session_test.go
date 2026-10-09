package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"

	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestInterruptedTraceDrainsFinalDiagnostics(t *testing.T) {
	for _, mode := range []model.TraceMode{model.TraceModePod, model.TraceModeService} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := make(chan model.Observation)
			failures := make(chan error)
			streams := []*kube.AgentStream{{Observations: input, Errors: failures}}
			deliveryCtx, cleanup := traceStreamContext(ctx, streams)
			defer func() {
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			}()
			traceContext := model.TraceContext{Mode: mode}
			observations, errors := mergeStreams(deliveryCtx, streams...)
			if mode == model.TraceModePod {
				observations = filterPodPathObservations(deliveryCtx, traceContext, observations)
			} else {
				observations = filterTraceObservations(deliveryCtx, traceContext, observations)
			}
			observations = prependTraceContext(deliveryCtx, "test", traceContext, observations)
			cancel()
			go func() {
				defer close(input)
				defer close(failures)
				input <- model.Observation{
					SchemaVersion: model.SchemaVersion, Kind: model.KindStatus,
					AttachmentID: "source", Side: "source", Final: true, Complete: true,
					InterfaceKind: "netkit", InterfaceMode: "L3",
					Diagnostics: []model.HookDiagnostics{{Hook: "tcx/ingress", Seen: 2, Emitted: 2}},
				}
			}()
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			if err := consume(command, ctx, "test", observations, errors, true); err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(&output)
			var initial, final model.Observation
			if err := decoder.Decode(&initial); err != nil {
				t.Fatal(err)
			}
			if err := decoder.Decode(&final); err != nil {
				t.Fatal(err)
			}
			if !final.Final || !final.Complete || final.InterfaceKind != "netkit" ||
				len(final.Diagnostics) != 1 || final.Diagnostics[0].Emitted != 2 {
				t.Fatalf("final status lost on interruption: %+v", final)
			}
		})
	}
}
