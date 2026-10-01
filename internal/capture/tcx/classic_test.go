package tcx

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
)

func TestClassicFilterUsesDirectionParentAndDirectAction(t *testing.T) {
	target := capture.Target{SessionID: "session", AttachID: "source"}
	ingress := classicFilter(12, netlink.HANDLE_MIN_INGRESS, 21, target)
	egress := classicFilter(12, netlink.HANDLE_MIN_EGRESS, 22, target)
	if ingress.Parent != netlink.HANDLE_MIN_INGRESS || egress.Parent != netlink.HANDLE_MIN_EGRESS {
		t.Fatalf("parents ingress=%#x egress=%#x", ingress.Parent, egress.Parent)
	}
	if ingress.Protocol != unix.ETH_P_ALL || egress.Protocol != unix.ETH_P_ALL {
		t.Fatalf("protocols ingress=%d egress=%d", ingress.Protocol, egress.Protocol)
	}
	if !ingress.DirectAction || !egress.DirectAction {
		t.Fatal("classic filters must use direct action")
	}
	if ingress.Fd != 21 || egress.Fd != 22 {
		t.Fatalf("program fds ingress=%d egress=%d", ingress.Fd, egress.Fd)
	}
}

func TestClassicFilterIdentitySeparatesAttachments(t *testing.T) {
	first := classicFilter(12, netlink.HANDLE_MIN_INGRESS, 21, capture.Target{
		SessionID: "session", AttachID: "source",
	})
	second := classicFilter(12, netlink.HANDLE_MIN_INGRESS, 21, capture.Target{
		SessionID: "session", AttachID: "backend",
	})
	if first.Handle == second.Handle && first.Priority == second.Priority {
		t.Fatalf("filter identities collide: handle=%#x priority=%d", first.Handle, first.Priority)
	}
}

func TestClassicObservationMetadata(t *testing.T) {
	observation := observationFromRawWithHook(
		capture.Target{}, bpfEvent{}, 0, "host-veth/tc", "node-transit/tc", "classic TC hook",
	)
	if observation.Point != "host-veth/tc" {
		t.Fatalf("point = %q", observation.Point)
	}
	if len(observation.Evidence) != 2 || observation.Evidence[1] != "classic TC hook" {
		t.Fatalf("evidence = %#v", observation.Evidence)
	}
}
