package agent

import "testing"

func TestKernelAtLeast(t *testing.T) {
	if !kernelAtLeast("6.8.12-kind", 6, 6) {
		t.Fatal("expected 6.8 to satisfy 6.6")
	}
	if kernelAtLeast("6.1.0", 6, 6) {
		t.Fatal("expected 6.1 not to satisfy 6.6")
	}
}

func TestProbeLocalReportsPacketStrategies(t *testing.T) {
	compatibility := ProbeLocal()
	seen := make(map[string]bool)
	for _, capability := range compatibility.Capabilities {
		seen[capability.Name] = true
	}
	for _, name := range []string{"TCX strategy", "classic TC strategy"} {
		if !seen[name] {
			t.Fatalf("missing capability %q", name)
		}
	}
}
