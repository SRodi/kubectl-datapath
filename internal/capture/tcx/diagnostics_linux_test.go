//go:build linux

package tcx

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Run explicitly on a Linux host with BPF privileges, without attaching to live interfaces.
func TestPacketDiagnosticsBPF(t *testing.T) {
	if os.Getenv("DATAPATH_BPF_TEST") != "1" {
		t.Skip("set DATAPATH_BPF_TEST=1 on a privileged Linux host")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objects bpfObjects
	if err := loadBpfObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Error(err)
		}
	})
	s := session{objects: objects, packetHooks: []string{"tcx/ingress", "tcx/egress"}}
	packet := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14] = 0x45
	packet[23] = 6
	packet[46] = 0x50
	packet[47] = 0x02
	zero := uint32(0)
	for _, mode := range []uint8{0, 1, 2} {
		if err := objects.CaptureModes.Update(&zero, &mode, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for _, program := range []*ebpf.Program{objects.ObserveIngress, objects.ObserveEgress} {
			for _, input := range [][]byte{packet, make([]byte, 54)} {
				result, _, err := program.Test(input)
				if err != nil {
					t.Fatal(err)
				}
				if result != ^uint32(0) {
					t.Fatalf("capture changed forwarding verdict: %d", result)
				}
			}
		}
	}
	diagnostics, err := s.readDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	for _, counters := range diagnostics {
		if counters.Seen != 6 || counters.ParseRejected != 3 || counters.Filtered != 2 ||
			counters.Emitted != 1 || counters.Lost != 0 {
			t.Fatalf("unexpected diagnostics: %+v", counters)
		}
	}
	// Fill the unread ring buffer to verify loss is distinct from parse/filter rejection.
	mode := uint8(0)
	if err := objects.CaptureModes.Update(&zero, &mode, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.ObserveIngress.Run(&ebpf.RunOptions{Data: packet, Repeat: 20000}); err != nil {
		t.Fatal(err)
	}
	diagnostics, err = s.readDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	counters := diagnostics[0]
	if counters.Lost == 0 || counters.Seen != counters.ParseRejected+counters.Filtered+counters.Emitted+counters.Lost {
		t.Fatalf("loss accounting mismatch: %+v", counters)
	}
}
