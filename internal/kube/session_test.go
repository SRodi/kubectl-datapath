package kube

import (
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
