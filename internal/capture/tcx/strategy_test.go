package tcx

import (
	"net/netip"
	"testing"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestObservationCarriesInterfaceMetadata(t *testing.T) {
	for kind, mode := range map[string]string{"veth": "", "netkit": "L3"} {
		target := capture.Target{
			Interface: "pod-peer", InterfaceKind: kind, InterfaceMode: mode,
			InterfaceMaster: "nk-vrf", InterfaceVRFTable: 100,
		}
		observation := observationFromRaw(target, bpfEvent{Kind: 1, Ifindex: 14, Direction: 1}, 0)
		if observation.Point != "pod-boundary/tcx" || observation.InterfaceKind != kind ||
			observation.InterfaceMode != mode || observation.InterfaceMaster != "nk-vrf" ||
			observation.InterfaceVRFTable != 100 || observation.InterfaceIdx != 14 {
			t.Fatalf("interface metadata lost: %+v", observation)
		}
	}
}

func TestObservationFromRawDecodesVXLANTransit(t *testing.T) {
	raw := bpfEvent{
		Kind: 3, MonotonicNs: 42, Ifindex: 7, PacketLength: 150,
		Family: 4, Protocol: 6, Direction: 2,
		SrcAddr: [16]uint8{10, 244, 0, 5}, DstAddr: [16]uint8{10, 244, 1, 8},
		SrcPort: 40000, DstPort: 80, TcpFlags: 0x02, TcpSequence: 100,
		Encapsulation: 2, TunnelId: 1, OuterFamily: 4,
		OuterSrcAddr: [16]uint8{172, 18, 0, 2}, OuterDstAddr: [16]uint8{172, 18, 0, 3},
		OuterSrcPort: 40001, OuterDstPort: 8472,
	}
	observation := observationFromRaw(capture.Target{
		SessionID: "session", AttachID: "transit-source-worker-b",
		Side: "transit-source", Node: "worker-a", Interface: "eth0",
	}, raw, 1000)
	if observation.Kind != model.KindTransit ||
		observation.Encapsulation != model.EncapsulationVXLAN ||
		observation.TunnelID != 1 ||
		observation.SrcAddr != netip.MustParseAddr("10.244.0.5") ||
		observation.DstAddr != netip.MustParseAddr("10.244.1.8") ||
		observation.OuterSrcAddr != netip.MustParseAddr("172.18.0.2") ||
		observation.OuterDstAddr != netip.MustParseAddr("172.18.0.3") ||
		observation.OuterDstPort != 8472 ||
		observation.Direction != model.DirectionEgress ||
		observation.Confidence != model.ConfidenceCorrelated {
		t.Fatalf("observation = %#v", observation)
	}
}

func TestObservationFromRawDecodesNativeICMPTransit(t *testing.T) {
	raw := bpfEvent{
		Kind: 3, MonotonicNs: 42, Ifindex: 7, PacketLength: 84,
		Family: 4, Protocol: 1, Direction: 1,
		SrcAddr: [16]uint8{10, 244, 2, 3}, DstAddr: [16]uint8{10, 244, 1, 7},
		Encapsulation: 1,
	}
	observation := observationFromRaw(capture.Target{
		SessionID: "session", AttachID: "transit-destination-worker-b",
		Side: "transit-destination", Node: "worker-b", Interface: "eth0",
	}, raw, 1000)
	if observation.Kind != model.KindTransit ||
		observation.Protocol != 1 ||
		observation.Encapsulation != model.EncapsulationNative ||
		observation.SrcAddr != netip.MustParseAddr("10.244.2.3") ||
		observation.DstAddr != netip.MustParseAddr("10.244.1.7") ||
		observation.Direction != model.DirectionIngress ||
		observation.Confidence != model.ConfidenceCorrelated {
		t.Fatalf("observation = %#v", observation)
	}
}
