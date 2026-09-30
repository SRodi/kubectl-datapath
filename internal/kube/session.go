package kube

import (
	"bufio"
	"context"
	"fmt"
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
	close        func()
}

func (s *AgentStream) Close() {
	if s.close != nil {
		s.close()
	}
}

func (c *Client) StartAgent(ctx context.Context, options AgentOptions, index *enrich.Index) (*AgentStream, error) {
	created, err := c.Clientset.CoreV1().Pods(options.Namespace).Create(ctx, AgentPod(options), metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create agent Pod: %w", err)
	}
	cleanupOnce := sync.Once{}
	cleanup := func() {
		// Agent Pods are disposable; delete immediately and guard every cleanup path.
		cleanupOnce.Do(func() {
			grace := int64(0)
			_ = c.Clientset.CoreV1().Pods(options.Namespace).Delete(context.Background(), created.Name, metav1.DeleteOptions{
				GracePeriodSeconds: &grace,
			})
		})
	}
	if err := c.waitForAgent(ctx, options.Namespace, created.Name); err != nil {
		cleanup()
		return nil, err
	}

	logs, err := c.Clientset.CoreV1().Pods(options.Namespace).GetLogs(created.Name, &corev1.PodLogOptions{
		Container: "agent",
		Follow:    true,
	}).Stream(ctx)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("stream agent logs: %w", err)
	}

	observations := make(chan model.Observation, 1024)
	errors := make(chan error, 1)
	go func() {
		defer close(observations)
		defer close(errors)
		defer logs.Close()
		scanner := bufio.NewScanner(logs)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			observation, err := model.Decode(scanner.Bytes())
			if err != nil {
				errors <- fmt.Errorf("decode agent %s output %q: %w", created.Name, scanner.Text(), err)
				return
			}
			if index != nil {
				observation = index.Apply(observation)
			}
			select {
			case observations <- observation:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errors <- fmt.Errorf("read agent %s output: %w", created.Name, err)
		}
	}()

	return &AgentStream{
		Observations: observations,
		Errors:       errors,
		AttachmentID: options.AttachmentID,
		Side:         options.Side,
		close:        cleanup,
	}, nil
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
