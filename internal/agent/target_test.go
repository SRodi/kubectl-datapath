package agent

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestTargetResolverIndexesMultiplePodUIDs(t *testing.T) {
	procRoot := t.TempDir()
	const podA = "11111111-1111-1111-1111-111111111111"
	const podB = "22222222-2222-2222-2222-222222222222"
	pidsByUID := map[string][]string{
		podA: {"111", "112"},
		podB: {"221"},
	}
	for podUID, pids := range pidsByUID {
		for _, pid := range pids {
			processRoot := filepath.Join(procRoot, pid)
			if err := os.MkdirAll(processRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			cgroup := "0::/kubepods.slice/kubepods-burstable-pod" + podUID + ".slice/container.scope\n"
			if err := os.WriteFile(filepath.Join(processRoot, "cgroup"), []byte(cgroup), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	resolver, err := NewTargetResolver(procRoot, t.TempDir(), []string{podA, podB})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resolver.pidsByUID[podA], []int{111, 112}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pod A PIDs = %v, want %v", got, want)
	}
	if got, want := resolver.pidsByUID[podB], []int{221}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pod B PIDs = %v, want %v", got, want)
	}
}

func TestTargetResolverMatchesUnderscoredPodUID(t *testing.T) {
	procRoot := t.TempDir()
	processRoot := filepath.Join(procRoot, "321")
	if err := os.MkdirAll(processRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(processRoot, "cgroup"),
		[]byte("0::/kubepods.slice/pod12345678_1234_1234_1234_123456789abc\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	const podUID = "12345678-1234-1234-1234-123456789abc"
	resolver, err := NewTargetResolver(procRoot, t.TempDir(), []string{podUID})
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.pidsByUID[podUID]; !reflect.DeepEqual(got, []int{321}) {
		t.Fatalf("indexed PIDs = %v, want [321]", got)
	}
}
