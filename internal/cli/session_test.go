package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestCaptureWatchContextStopsOnlyAfterAllAgentsFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, second := make(chan struct{}), make(chan struct{})
	watchCtx, stop := captureWatchContext(ctx, []*kube.AgentStream{{Done: first}, {Done: second}})
	defer stop()
	close(first)
	select {
	case <-watchCtx.Done():
		t.Fatal("watchers stopped while a capture was still running")
	case <-time.After(10 * time.Millisecond):
	}
	close(second)
	select {
	case <-watchCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchers did not stop after all agents completed")
	}
	if ctx.Err() != nil {
		t.Fatal("capture completion cancelled the results view")
	}
}

func TestCaptureWatchContextStopsOnClientCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	watchCtx, stop := captureWatchContext(ctx, []*kube.AgentStream{{Done: make(chan struct{})}})
	defer stop()
	cancel()
	select {
	case <-watchCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchers did not stop on client cancellation")
	}
}

func TestCompletedServiceCaptureClosesMergedStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := make(chan model.Observation, 1)
	failures := make(chan error)
	done := make(chan struct{})
	streams := []*kube.AgentStream{{Observations: input, Errors: failures, Done: done}}
	watchCtx, stop := captureWatchContext(ctx, streams)
	defer stop()
	client := &kube.Client{Clientset: fake.NewClientset()}
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	streams = append(streams,
		startPolicyContextStream(command, watchCtx, client, "test", model.TraceContext{}, &corev1.Pod{}, nil),
		startServiceTopologyStream(command, watchCtx, client, &corev1.Pod{}, model.Endpoint{}, nil),
	)
	observations, failuresOut := mergeStreams(ctx, streams...)
	finished := make(chan error, 1)
	go func() {
		finished <- consume(command, ctx, "test", observations, failuresOut, true)
	}()
	input <- model.Observation{
		SchemaVersion: model.SchemaVersion, Kind: model.KindStatus,
		AttachmentID: "source", Final: true, Complete: true,
	}
	close(input)
	close(failures)
	close(done)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Service metadata watchers kept the completed capture open")
	}
	var final model.Observation
	if err := json.NewDecoder(&output).Decode(&final); err != nil {
		t.Fatal(err)
	}
	if !final.Final || !final.Complete {
		t.Fatalf("lost final status: %+v", final)
	}
	if ctx.Err() != nil {
		t.Fatal("completion cancelled the results view")
	}
}

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
