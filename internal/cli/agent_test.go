package cli

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type fakeCaptureSession struct {
	events chan model.Observation
	errors chan error
}

func (s *fakeCaptureSession) Events() <-chan model.Observation { return s.events }
func (s *fakeCaptureSession) Errors() <-chan error             { return s.errors }
func (s *fakeCaptureSession) Close() error                     { return nil }

func TestMergeCaptureSessionsPreservesAttachmentIdentity(t *testing.T) {
	first := &fakeCaptureSession{
		events: make(chan model.Observation, 1),
		errors: make(chan error, 1),
	}
	second := &fakeCaptureSession{
		events: make(chan model.Observation, 1),
		errors: make(chan error, 1),
	}
	first.events <- model.Observation{Kind: model.KindStatus, AttachmentID: "source", Side: "source"}
	second.events <- model.Observation{Kind: model.KindStatus, AttachmentID: "transit", Side: "transit-source"}
	close(first.events)
	close(first.errors)
	close(second.events)
	close(second.errors)

	events, errorsChannel := mergeCaptureSessions(context.Background(), []namedCaptureSession{
		{name: "source", session: first},
		{name: "transit", session: second},
	})
	seen := make(map[string]bool)
	for observation := range events {
		seen[observation.AttachmentID] = true
	}
	if !seen["source"] || !seen["transit"] {
		t.Fatalf("merged attachments = %#v", seen)
	}
	if err := <-errorsChannel; err != nil {
		t.Fatal(err)
	}
}

func TestMergeCaptureSessionsDrainsFinalEventsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &fakeCaptureSession{
		events: make(chan model.Observation, 1),
		errors: make(chan error),
	}
	session.events <- model.Observation{
		Kind: model.KindStatus, AttachmentID: "source", Side: "source", Final: true, Complete: true,
	}
	close(session.events)
	close(session.errors)

	events, streamErrors := mergeCaptureSessions(ctx, []namedCaptureSession{
		{name: "source", session: session},
	})
	observation, ok := <-events
	if !ok || !observation.Final || !observation.Complete {
		t.Fatalf("final observation = %+v, ok=%t", observation, ok)
	}
	for range events {
	}
	if err := <-streamErrors; err != nil {
		t.Fatal(err)
	}
}

func TestMergeCaptureSessionsAttributesErrors(t *testing.T) {
	session := &fakeCaptureSession{
		events: make(chan model.Observation),
		errors: make(chan error, 1),
	}
	close(session.events)
	session.errors <- errors.New("ring buffer failed")
	close(session.errors)
	_, errorsChannel := mergeCaptureSessions(context.Background(), []namedCaptureSession{
		{name: "backend-1", session: session},
	})
	err := <-errorsChannel
	if err == nil || err.Error() != "backend-1 capture: ring buffer failed" {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFlowAddresses(t *testing.T) {
	got, err := parseFlowAddresses([]string{"10.244.0.10", "10.244.1.20"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.244.0.10"), netip.MustParseAddr("10.244.1.20")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("flow addresses = %#v", got)
	}
	if _, err := parseFlowAddresses([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid flow address must fail")
	}
}
