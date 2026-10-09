package kube

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SRodi/kubectl-datapath/internal/enrich"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

type AgentStream struct {
	Observations <-chan model.Observation
	Errors       <-chan error
	AttachmentID string
	Side         string
	Done         <-chan struct{}
	close        func() error
	cancel       context.CancelFunc
	closeOnce    sync.Once
	closeErr     error
}

const agentShutdownTimeout = 10 * time.Second

type sequenceState struct {
	sequence      uint64
	ringLost      uint64
	transportLost uint64
}

type sequenceTracker map[string]sequenceState

func (t sequenceTracker) annotate(observation model.Observation) model.Observation {
	if observation.Sequence == 0 {
		return observation
	}
	key := observation.AttachmentID
	if key == "" {
		key = observation.Side
	}
	state := t[key]
	if observation.Sequence > state.sequence+1 {
		gap := observation.Sequence - state.sequence - 1
		ringLoss := uint64(0)
		if observation.Lost > state.ringLost {
			ringLoss = observation.Lost - state.ringLost
		}
		if gap > ringLoss {
			state.transportLost += gap - ringLoss
		}
	}
	if observation.Sequence > state.sequence {
		state.sequence = observation.Sequence
		state.ringLost = observation.Lost
	}
	observation.TransportLost = state.transportLost
	t[key] = state
	return observation
}

func (s *AgentStream) Close() error {
	s.closeOnce.Do(func() {
		if s.close != nil {
			s.closeErr = s.close()
		}
		if s.Done != nil {
			timer := time.NewTimer(agentShutdownTimeout)
			defer timer.Stop()
			select {
			case <-s.Done:
			case <-timer.C:
				s.closeErr = errors.Join(s.closeErr, fmt.Errorf(
					"agent log stream did not finish within %s; final capture status may be missing",
					agentShutdownTimeout,
				))
			}
		}
		if s.cancel != nil {
			s.cancel()
		}
	})
	return s.closeErr
}

func (c *Client) StartAgent(ctx context.Context, options AgentOptions, index *enrich.Index) (*AgentStream, error) {
	created, err := c.Clientset.CoreV1().Pods(options.Namespace).Create(ctx, AgentPod(options), metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create agent Pod: %w", err)
	}
	cleanupOnce := sync.Once{}
	var cleanupErr error
	cleanup := func() error {
		cleanupOnce.Do(func() {
			cleanupErr = c.deleteAgentPod(created)
		})
		return cleanupErr
	}
	if err := c.waitForAgent(ctx, options.Namespace, created.Name); err != nil {
		return nil, errors.Join(err, cleanup())
	}

	streamCtx, cancelStream := context.WithCancel(context.Background())
	logs, err := c.Clientset.CoreV1().Pods(options.Namespace).GetLogs(created.Name, &corev1.PodLogOptions{
		Container: "agent",
		Follow:    true,
	}).Stream(streamCtx)
	if err != nil {
		cancelStream()
		return nil, errors.Join(fmt.Errorf("stream agent logs: %w", err), cleanup())
	}

	observations := make(chan model.Observation, 1024)
	streamErrors := make(chan error, 1)
	done := make(chan struct{})
	expectedSides := expectedAttachmentSides(options)
	expected := sortedAttachmentIDs(expectedSides)
	go func() {
		defer close(done)
		defer close(observations)
		defer close(streamErrors)
		defer cancelStream()
		scanner := bufio.NewScanner(logs)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		sequences := make(sequenceTracker)
		finalStatuses := make(map[string]bool, len(expected))
		var streamErr error
		for scanner.Scan() {
			observation, err := model.Decode(scanner.Bytes())
			if err != nil {
				streamErr = fmt.Errorf("decode agent %s output %q: %w", created.Name, scanner.Text(), err)
				break
			}
			if observation.Final {
				finalStatuses[observation.AttachmentID] = observation.Complete
			}
			observation = sequences.annotate(observation)
			if index != nil {
				observation = index.Apply(observation)
			}
			select {
			case observations <- observation:
			case <-streamCtx.Done():
				break
			}
			if streamCtx.Err() != nil {
				break
			}
		}
		if err := scanner.Err(); err != nil && streamCtx.Err() == nil {
			streamErr = errors.Join(streamErr, fmt.Errorf("read agent %s output: %w", created.Name, err))
		}
		if streamCtx.Err() == nil {
			if missing := missingFinalStatuses(expected, finalStatuses); len(missing) > 0 {
			sendMissing:
				for _, attachment := range missing {
					observation := model.Observation{
						SchemaVersion: model.SchemaVersion,
						Kind:          model.KindStatus,
						SessionID:     options.SessionID,
						AttachmentID:  attachment,
						Side:          expectedSides[attachment],
						Node:          options.Node,
						WallTime:      time.Now(),
						Final:         true,
						Complete:      false,
						Message:       "agent log stream ended without a final capture status",
					}
					if index != nil {
						observation = index.Apply(observation)
					}
					select {
					case observations <- observation:
					case <-streamCtx.Done():
						break sendMissing
					}
				}
				streamErr = errors.Join(streamErr, fmt.Errorf(
					"agent %s ended without final capture status for attachments: %s",
					created.Name, strings.Join(missing, ", "),
				))
			} else if incomplete := incompleteFinalStatuses(expected, finalStatuses); len(incomplete) > 0 {
				streamErr = errors.Join(streamErr, fmt.Errorf(
					"agent %s reported incomplete final capture status for attachments: %s",
					created.Name, strings.Join(incomplete, ", "),
				))
			}
		}
		if err := logs.Close(); err != nil && streamCtx.Err() == nil {
			streamErr = errors.Join(streamErr, fmt.Errorf("close agent %s log stream: %w", created.Name, err))
		}
		streamErr = errors.Join(streamErr, cleanup())
		if streamErr != nil {
			streamErrors <- streamErr
		}
	}()

	return &AgentStream{
		Observations: observations,
		Errors:       streamErrors,
		AttachmentID: options.AttachmentID,
		Side:         options.Side,
		close:        cleanup,
		Done:         done,
		cancel:       cancelStream,
	}, nil
}

func (c *Client) deleteAgentPod(pod *corev1.Pod) error {
	grace := int64(5)
	options := metav1.DeleteOptions{
		GracePeriodSeconds: &grace,
		Preconditions:      &metav1.Preconditions{UID: &pod.UID},
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = c.Clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, options)
		cancel()
		if err == nil || apierrors.IsNotFound(err) {
			return nil
		}
		if !retryableAgentDelete(err) {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
		}
	}
	return fmt.Errorf("delete agent Pod %s/%s failed; Pod may remain: %w", pod.Namespace, pod.Name, err)
}

func retryableAgentDelete(err error) bool {
	var networkError net.Error
	return apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) || apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) || errors.As(err, &networkError) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func expectedAttachmentSides(options AgentOptions) map[string]string {
	sides := make(map[string]string)
	for _, target := range options.Targets {
		if target.AttachmentID != "" {
			sides[target.AttachmentID] = target.Side
		}
	}
	if len(sides) == 0 && options.AttachmentID != "" {
		sides[options.AttachmentID] = options.Side
	}
	return sides
}

func sortedAttachmentIDs(sides map[string]string) []string {
	attachments := make([]string, 0, len(sides))
	for attachment := range sides {
		attachments = append(attachments, attachment)
	}
	sort.Strings(attachments)
	return attachments
}

func missingFinalStatuses(expected []string, statuses map[string]bool) []string {
	var missing []string
	for _, attachment := range expected {
		if _, ok := statuses[attachment]; !ok {
			missing = append(missing, attachment)
		}
	}
	return missing
}

func incompleteFinalStatuses(expected []string, statuses map[string]bool) []string {
	var incomplete []string
	for _, attachment := range expected {
		if complete, ok := statuses[attachment]; ok && !complete {
			incomplete = append(incomplete, attachment)
		}
	}
	return incomplete
}

func (c *Client) waitForAgent(ctx context.Context, namespace, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := c.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("agent Pod disappeared before starting")
			}
			return fmt.Errorf("get agent Pod: %w", err)
		}
		switch pod.Status.Phase {
		case corev1.PodRunning:
			return nil
		case corev1.PodFailed:
			return fmt.Errorf("agent Pod failed: %s: %s", pod.Status.Reason, pod.Status.Message)
		case corev1.PodSucceeded:
			return fmt.Errorf("agent Pod exited before observation started")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for agent Pod: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
