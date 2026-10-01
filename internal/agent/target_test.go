package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPodCgroupPathReadsUnifiedHierarchy(t *testing.T) {
	root := t.TempDir()
	pid := 42
	path := filepath.Join(root, "42")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "7:cpu:/legacy\n0::/kubepods.slice/pod123/container\n"
	if err := os.WriteFile(filepath.Join(path, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := podCgroupPath(root, pid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/kubepods.slice/pod123/container" {
		t.Fatalf("path = %q", got)
	}
}

func TestPodPrimaryInterfaceUsesIPv4DefaultRoute(t *testing.T) {
	root := t.TempDir()
	pid := 42
	path := filepath.Join(root, "42", "net")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	route := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"net1 00000000 0100000A 0003 0 0 0 00000000 0 0 0\n"
	if err := os.WriteFile(filepath.Join(path, "route"), []byte(route), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := podPrimaryInterface(root, pid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "net1" {
		t.Fatalf("interface = %q, want net1", got)
	}
}

func TestPodPrimaryInterfaceUsesIPv6DefaultRoute(t *testing.T) {
	root := t.TempDir()
	pid := 42
	path := filepath.Join(root, "42", "net")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	route := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000000 00000000 00000000 00000001 net2\n"
	if err := os.WriteFile(filepath.Join(path, "ipv6_route"), []byte(route), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := podPrimaryInterface(root, pid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "net2" {
		t.Fatalf("interface = %q, want net2", got)
	}
}

func TestPodPrimaryInterfaceFallsBackToOnlyNonLoopbackInterface(t *testing.T) {
	root := t.TempDir()
	pid := 42
	netRoot := filepath.Join(root, "42", "root", "sys", "class", "net")
	for _, name := range []string{"lo", "pod0"} {
		if err := os.MkdirAll(filepath.Join(netRoot, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := podPrimaryInterface(root, pid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "pod0" {
		t.Fatalf("interface = %q, want pod0", got)
	}
}
