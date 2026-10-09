package kube

import (
	"errors"
	"reflect"
	"testing"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestSequenceTrackerSeparatesRingAndTransportLoss(t *testing.T) {
	tracker := make(sequenceTracker)
	observations := []model.Observation{
		{AttachmentID: "source", Sequence: 1},
		{AttachmentID: "source", Sequence: 3, Lost: 1},
		{AttachmentID: "source", Sequence: 6, Lost: 2},
		{AttachmentID: "source", Sequence: 7, Lost: 2},
	}
	want := []uint64{0, 0, 1, 1}
	for index, observation := range observations {
		got := tracker.annotate(observation)
		if got.TransportLost != want[index] {
			t.Fatalf("observation %d transport loss = %d, want %d", index, got.TransportLost, want[index])
		}
	}
}

func TestSequenceTrackerKeepsAttachmentsIndependent(t *testing.T) {
	tracker := make(sequenceTracker)
	source := tracker.annotate(model.Observation{
		AttachmentID: "source", Sequence: 3,
	})
	backend := tracker.annotate(model.Observation{
		AttachmentID: "backend", Sequence: 1,
	})
	if source.TransportLost != 2 {
		t.Fatalf("source transport loss = %d, want 2", source.TransportLost)
	}
	if backend.TransportLost != 0 {
		t.Fatalf("backend transport loss = %d, want 0", backend.TransportLost)
	}
}

func TestSequenceTrackerIgnoresUnsequencedStatus(t *testing.T) {
	tracker := make(sequenceTracker)
	status := tracker.annotate(model.Observation{
		AttachmentID: "source", Lost: 4,
	})
	packet := tracker.annotate(model.Observation{
		AttachmentID: "source", Sequence: 5, Lost: 4,
	})
	if status.TransportLost != 0 || packet.TransportLost != 0 {
		t.Fatalf("status=%d packet=%d, want no transport loss", status.TransportLost, packet.TransportLost)
	}
}

func TestSequenceTrackerPreservesFinalWatermarkAndDetectsTailLoss(t *testing.T) {
	tracker := make(sequenceTracker)
	tracker.annotate(model.Observation{AttachmentID: "source", Sequence: 1})
	final := tracker.annotate(model.Observation{
		AttachmentID: "source", Sequence: 4, Lost: 1, Final: true, Complete: true,
	})
	if !final.Final || !final.Complete || final.Sequence != 4 {
		t.Fatalf("final watermark was not preserved: %+v", final)
	}
	if final.TransportLost != 1 {
		t.Fatalf("tail transport loss = %d, want 1", final.TransportLost)
	}
}

func TestFinalStatusValidationCoversEveryExpectedAttachment(t *testing.T) {
	expected := []string{"source", "backend-1", "backend-2"}
	statuses := map[string]bool{"source": true, "backend-1": false}
	if got, want := missingFinalStatuses(expected, statuses), []string{"backend-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing statuses = %v, want %v", got, want)
	}
	if got, want := incompleteFinalStatuses(expected, statuses), []string{"backend-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("incomplete statuses = %v, want %v", got, want)
	}
}

func TestAgentStreamCloseReturnsCleanupErrorOnce(t *testing.T) {
	want := errors.New("delete failed")
	var calls int
	done := make(chan struct{})
	close(done)
	stream := &AgentStream{
		close: func() error {
			calls++
			return want
		},
		Done: done,
	}
	for range 2 {
		if err := stream.Close(); !errors.Is(err, want) {
			t.Fatalf("close error = %v, want %v", err, want)
		}
	}
	if calls != 1 {
		t.Fatalf("cleanup called %d times, want once", calls)
	}
}

func FuzzSequenceTrackerNeverDecreasesTransportLoss(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint64(0), uint64(0))
	f.Add(uint64(4), uint64(9), uint64(1), uint64(3))
	f.Fuzz(func(t *testing.T, first, second, firstLost, secondLost uint64) {
		if first == 0 || second == 0 {
			t.Skip()
		}
		tracker := make(sequenceTracker)
		one := tracker.annotate(model.Observation{
			AttachmentID: "source", Sequence: first, Lost: firstLost,
		})
		two := tracker.annotate(model.Observation{
			AttachmentID: "source", Sequence: second, Lost: secondLost,
		})
		if two.TransportLost < one.TransportLost {
			t.Fatalf("transport loss decreased from %d to %d", one.TransportLost, two.TransportLost)
		}
	})
}
