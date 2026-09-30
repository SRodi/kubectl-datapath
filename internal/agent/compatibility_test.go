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
