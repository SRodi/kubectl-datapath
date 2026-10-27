package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/SRodi/kubectl-datapath/internal/agent"
	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

func newAgentCommand() *cobra.Command {
	var (
		procRoot     string
		cgroupRoot   string
		sessionID    string
		node         string
		targetValues []string
	)
	command := &cobra.Command{
		Use:    "agent",
		Short:  "Run the node-local capture agent",
		Hidden: true,
		RunE: func(command *cobra.Command, _ []string) (commandErr error) {
			sessions := make([]namedCaptureSession, 0, len(targetValues))
			defer func() {
				commandErr = errors.Join(commandErr, closeCaptureSessions(sessions))
			}()
			targets := make([]kube.AgentTarget, 0, len(targetValues))
			for _, value := range targetValues {
				var target kube.AgentTarget
				if err := json.Unmarshal([]byte(value), &target); err != nil {
					return fmt.Errorf("decode agent target: %w", err)
				}
				targets = append(targets, target)
			}
			var resolver *agent.TargetResolver
			var podUIDs []string
			for _, target := range targets {
				if target.RouteTo == "" && target.PodUID != "" {
					podUIDs = append(podUIDs, target.PodUID)
				}
			}
			if len(podUIDs) > 0 {
				createdResolver, err := agent.NewTargetResolver(procRoot, cgroupRoot, podUIDs)
				if err != nil {
					return fmt.Errorf("index target Pod processes: %w", err)
				}
				resolver = createdResolver
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			strategies := agent.NewCaptureStrategies()
			for _, target := range targets {
				resolved, err := resolveAgentTarget(
					target, sessionID, node, resolver,
				)
				if err != nil {
					return fmt.Errorf("%s: %w", target.AttachmentID, err)
				}
				session, err := strategies.Open(ctx, resolved)
				if err != nil {
					return fmt.Errorf("%s: %w", target.AttachmentID, err)
				}
				sessions = append(sessions, namedCaptureSession{name: target.AttachmentID, session: session})
			}

			events, streamErrors := mergeCaptureSessions(ctx, sessions)
			encoder := json.NewEncoder(command.OutOrStdout())
			ctxDone := ctx.Done()
			var closing <-chan error
			var captureErr error
			for events != nil || streamErrors != nil || closing != nil {
				select {
				case <-ctxDone:
					ctxDone = nil
					result := make(chan error, 1)
					closing = result
					go func() {
						result <- closeCaptureSessions(sessions)
					}()
				case observation, ok := <-events:
					if !ok {
						events = nil
						continue
					}
					if err := encoder.Encode(observation); err != nil {
						return fmt.Errorf("encode observation: %w", err)
					}
				case err, ok := <-streamErrors:
					if !ok {
						streamErrors = nil
						continue
					}
					if err != nil {
						captureErr = errors.Join(captureErr, err)
						stop()
					}
				case err := <-closing:
					captureErr = errors.Join(captureErr, err)
					closing = nil
				}
			}
			return captureErr
		},
	}
	command.Flags().StringVar(&procRoot, "proc-root", "/host/proc", "host procfs mount")
	command.Flags().StringVar(&cgroupRoot, "cgroup-root", "/host/sys/fs/cgroup", "host cgroup v2 mount")
	command.Flags().StringVar(&sessionID, "session-id", "", "session identifier")
	command.Flags().StringVar(&node, "node", "", "node name")
	command.Flags().StringArrayVar(&targetValues, "target-json", nil, "JSON-encoded node-local capture target")
	return command
}

type namedCaptureSession struct {
	name    string
	session capture.Session
}

func parseFlowAddresses(values []string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("parse flow address %q: %w", value, err)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func resolveAgentTarget(
	spec kube.AgentTarget,
	sessionID, node string,
	resolver *agent.TargetResolver,
) (capture.Target, error) {
	target := capture.Target{
		CaptureConnect: spec.CaptureConnect,
		SessionID:      sessionID,
		AttachID:       spec.AttachmentID,
		Side:           spec.Side,
		Node:           node,
	}
	flowAddresses, err := parseFlowAddresses(spec.FlowAddresses)
	if err != nil {
		return capture.Target{}, err
	}
	target.FlowAddresses = flowAddresses
	switch {
	case spec.RouteTo != "":
		destination, err := netip.ParseAddr(spec.RouteTo)
		if err != nil {
			return capture.Target{}, fmt.Errorf("parse route destination %q: %w", spec.RouteTo, err)
		}
		target.Interface, err = agent.InterfaceForRoute(destination)
		if err != nil {
			return capture.Target{}, err
		}
		target.Transit = true
		if len(target.FlowAddresses) < 2 {
			return capture.Target{}, fmt.Errorf("transit capture requires at least two flow addresses")
		}
	case spec.PodUID != "":
		if resolver == nil {
			return capture.Target{}, fmt.Errorf("target Pod process index is unavailable")
		}
		resolved, err := resolver.TargetForPodUID(spec.PodUID)
		if err != nil {
			return capture.Target{}, fmt.Errorf("resolve target interface: %w", err)
		}
		target.Interface = resolved.Interface
		target.CgroupIDs = resolved.CgroupIDs
	default:
		return capture.Target{}, fmt.Errorf("one of Pod UID or route destination is required")
	}
	return target, nil
}

func mergeCaptureSessions(
	_ context.Context,
	sessions []namedCaptureSession,
) (<-chan model.Observation, <-chan error) {
	events := make(chan model.Observation, 1024)
	streamErrors := make(chan error, len(sessions))
	var wait sync.WaitGroup
	for _, current := range sessions {
		wait.Add(1)
		go func(current namedCaptureSession) {
			defer wait.Done()
			for observation := range current.session.Events() {
				events <- observation
			}
			if err := <-current.session.Errors(); err != nil {
				streamErrors <- fmt.Errorf("%s capture: %w", current.name, err)
			}
		}(current)
	}
	go func() {
		wait.Wait()
		close(events)
		close(streamErrors)
	}()
	return events, streamErrors
}

func closeCaptureSessions(sessions []namedCaptureSession) error {
	var errs []error
	for i := len(sessions) - 1; i >= 0; i-- {
		current := sessions[i]
		if err := current.session.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s close capture: %w", current.name, err))
		}
	}
	return errors.Join(errs...)
}
