package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/SRodi/kubectl-datapath/internal/enrich"
	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
	"github.com/SRodi/kubectl-datapath/internal/tui"
)

type traceOptions struct {
	kubeconfig           string
	context              string
	namespace            string
	agentNamespace       string
	agentImage           string
	agentImagePullSecret string
	noTUI                bool
}

func buildIndex(ctx context.Context, stderr io.Writer, client *kube.Client, targets ...*corev1.Pod) *enrich.Index {
	namespaces := make([]string, 0, len(targets))
	for _, target := range targets {
		namespaces = append(namespaces, target.Namespace)
	}
	index, warnings := enrich.BuildNamespaces(ctx, client.Clientset, namespaces...)
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "warning: metadata unavailable: %v\n", warning)
	}
	for _, target := range targets {
		for _, podIP := range target.Status.PodIPs {
			if address, err := modelAddress(podIP.IP); err == nil {
				index.AddEndpoint(model.Endpoint{
					Kind: model.EndpointPod, Namespace: target.Namespace, Name: target.Name,
					Node: target.Spec.NodeName, Address: address,
				})
			}
		}
	}
	return index
}

func modelAddress(value string) (address netip.Addr, err error) {
	return netip.ParseAddr(value)
}

func newSessionID() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func consume(command *cobra.Command, ctx context.Context, title string, observations <-chan model.Observation, errors <-chan error, noTUI bool) error {
	if noTUI {
		encoder := json.NewEncoder(command.OutOrStdout())
		for observations != nil || errors != nil {
			select {
			case observation, ok := <-observations:
				if !ok {
					observations = nil
					continue
				}
				if err := encoder.Encode(observation); err != nil {
					return err
				}
			case err, ok := <-errors:
				if !ok {
					errors = nil
					continue
				}
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	return tui.Run(ctx, title, observations, errors, os.Stdin, command.OutOrStdout())
}

// Stop agents on interruption, but keep the delivery pipeline alive until the
// consumer has drained their final counters. Cleanup also handles early errors.
func traceStreamContext(ctx context.Context, streams []*kube.AgentStream) (context.Context, func() error) {
	deliveryCtx, cancelDelivery := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	var closeOnce sync.Once
	var closeErr error
	closeStreams := func() error {
		closeOnce.Do(func() {
			closeErr = closeAgentStreams(streams)
		})
		return closeErr
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = closeStreams()
		case <-done:
		}
	}()
	return deliveryCtx, func() error {
		close(done)
		cancelDelivery()
		return closeStreams()
	}
}

func mergeStreams(ctx context.Context, streams ...*kube.AgentStream) (<-chan model.Observation, <-chan error) {
	observations := make(chan model.Observation, 1024)
	streamErrors := make(chan error, len(streams))
	var wait sync.WaitGroup
	for _, stream := range streams {
		wait.Add(1)
		go func(stream *kube.AgentStream) {
			defer wait.Done()
			for observation := range stream.Observations {
				select {
				case observations <- observation:
				case <-ctx.Done():
					return
				}
			}
			if err := <-stream.Errors; err != nil {
				streamErrors <- fmt.Errorf("%s attachment %s: %w", stream.Side, stream.AttachmentID, err)
			}
		}(stream)
	}
	go func() {
		wait.Wait()
		close(observations)
		close(streamErrors)
	}()
	return observations, streamErrors
}
