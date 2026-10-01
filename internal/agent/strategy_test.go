package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

type fakeStrategy struct {
	calls   int
	session capture.Session
	err     error
}

func (s *fakeStrategy) Name() string { return "fake" }

func (s *fakeStrategy) Open(context.Context, capture.Target) (capture.Session, error) {
	s.calls++
	return s.session, s.err
}

type inertSession struct{}

func (inertSession) Events() <-chan model.Observation {
	channel := make(chan model.Observation)
	close(channel)
	return channel
}
func (inertSession) Errors() <-chan error {
	channel := make(chan error)
	close(channel)
	return channel
}
func (inertSession) Close() error { return nil }

func TestCaptureStrategiesPreferTCX(t *testing.T) {
	tcxStrategy := &fakeStrategy{session: inertSession{}}
	classic := &fakeStrategy{session: inertSession{}}
	_, err := (CaptureStrategies{TCX: tcxStrategy, Classic: classic}).Open(
		context.Background(), capture.Target{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if tcxStrategy.calls != 1 || classic.calls != 0 {
		t.Fatalf("calls tcx=%d classic=%d", tcxStrategy.calls, classic.calls)
	}
}

func TestCaptureStrategiesFallBackWhenTCXUnsupported(t *testing.T) {
	tcxStrategy := &fakeStrategy{err: fmt.Errorf("attach TCX ingress: %w", unix.EOPNOTSUPP)}
	classic := &fakeStrategy{session: inertSession{}}
	_, err := (CaptureStrategies{TCX: tcxStrategy, Classic: classic}).Open(
		context.Background(), capture.Target{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if classic.calls != 1 {
		t.Fatalf("classic calls = %d, want 1", classic.calls)
	}
}

func TestCaptureStrategiesDoNotFallBackForConfigurationEINVAL(t *testing.T) {
	tcxStrategy := &fakeStrategy{err: fmt.Errorf("configure capture mode: %w", unix.EINVAL)}
	classic := &fakeStrategy{session: inertSession{}}
	_, err := (CaptureStrategies{TCX: tcxStrategy, Classic: classic}).Open(
		context.Background(), capture.Target{},
	)
	if err == nil || classic.calls != 0 {
		t.Fatalf("error=%v classic calls=%d", err, classic.calls)
	}
}

func TestCaptureStrategiesDoNotMaskTCXFailure(t *testing.T) {
	tcxStrategy := &fakeStrategy{err: errors.New("verifier rejected program")}
	classic := &fakeStrategy{session: inertSession{}}
	_, err := (CaptureStrategies{TCX: tcxStrategy, Classic: classic}).Open(
		context.Background(), capture.Target{},
	)
	if err == nil || classic.calls != 0 {
		t.Fatalf("error=%v classic calls=%d", err, classic.calls)
	}
}
