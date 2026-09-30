package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestTrackerMarksEventLossIncomplete(t *testing.T) {
	tracker := NewTracker()
	tracker.Observe(model.Observation{
		SchemaVersion: model.SchemaVersion,
		Kind:          model.KindPacket,
		WallTime:      time.Now(),
		Protocol:      6,
		SrcAddr:       netip.MustParseAddr("10.0.0.1"),
		DstAddr:       netip.MustParseAddr("10.0.0.2"),
		SrcPort:       40000,
		DstPort:       80,
		Lost:          3,
	})
	flows := tracker.Flows()
	if len(flows) != 1 || flows[0].Status != StatusIncomplete {
		t.Fatalf("flows = %+v", flows)
	}
}

func TestKeyIncludesProtocol(t *testing.T) {
	base := model.Observation{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1234,
		DstPort: 80,
	}
	tcp := base
	tcp.Protocol = 6
	udp := base
	udp.Protocol = 17
	if NewKey(tcp) == NewKey(udp) {
		t.Fatal("TCP and UDP keys must differ")
	}
}

func TestTrackerCallsOppositeDirectionAResponseObservation(t *testing.T) {
	tracker := NewTracker()
	base := model.Observation{
		SchemaVersion: model.SchemaVersion,
		Kind:          model.KindPacket,
		WallTime:      time.Now(),
		Protocol:      6,
		SrcAddr:       netip.MustParseAddr("10.0.0.1"),
		DstAddr:       netip.MustParseAddr("10.0.0.2"),
		SrcPort:       1234,
		DstPort:       80,
		Direction:     model.DirectionIngress,
	}
	tracker.Observe(base)
	base.SrcAddr, base.DstAddr = base.DstAddr, base.SrcAddr
	base.SrcPort, base.DstPort = base.DstPort, base.SrcPort
	base.Direction = model.DirectionEgress
	tracker.Observe(base)
	if got := tracker.Flows()[0].Status; got != StatusResponse {
		t.Fatalf("status = %q, want %q", got, StatusResponse)
	}
}

func TestTrackerReportsSYNRetransmissionsWithoutResponse(t *testing.T) {
	tracker := NewTracker()
	observation := model.Observation{
		Kind: model.KindPacket, WallTime: time.Now(), Protocol: 6,
		SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		Direction: model.DirectionIngress,
	}
	tracker.Observe(observation)
	observation.WallTime = observation.WallTime.Add(time.Second)
	tracker.Observe(observation)
	if got := tracker.Flows()[0].Status; got != StatusRetransmit {
		t.Fatalf("status = %q, want %q", got, StatusRetransmit)
	}
}
